// dns_sniffer.c
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <arpa/inet.h>

#include <pcap.h>
#include <sqlite3.h>
#include <curl/curl.h>
#include <json-c/json.h>

#include "table.h"

typedef struct {
    int type;
    int class;
    char name[256];
} DNS_Data;

pcap_t* handle = NULL;
pcap_dumper_t* dumper = NULL;
json_object* jarray = NULL;
sqlite3* db = NULL;
table_t* table = NULL;

char* dns_filters = NULL, *server_endpoint_url = NULL;
int max_count = -1;
int passed_count = 0;
int port = 53;

char* itos(int value) {
    // 12 bytes: 11 digits max for int32_t + 1 null terminator
    char* str = malloc(12);
    if (str) {
        snprintf(str, 12, "%d", value);
    }
    return str;
}

bool ends_with(const char *str, const char *suffix) {
    if (!str || !suffix) return false;
    size_t len_str = strlen(str), len_suffix = strlen(suffix);
    return len_suffix <= len_str && strcmp(str + len_str - len_suffix, suffix) == 0;
}

int bytesToInt(int count, ...) {
    va_list args;
    va_start(args, count);
    int result = 0;
    for (int i = 0; i < count; ++i) {
        unsigned char byte = (unsigned char)va_arg(args, int);
        result = (result << 8) | byte;
    }
    va_end(args);
    return result;
}

json_object* readJsonFromFile(char* filepath) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) return NULL;

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    rewind(fp);

    char *buffer = malloc(file_size + 1);
    if (!buffer) return NULL;
    fread(buffer, 1, file_size, fp);
    buffer[file_size] = '\0';
    fclose(fp);

    json_object* parsed_json = json_tokener_parse(buffer);
    free(buffer);
    return parsed_json;
}

int writeJsonToFile(const char* filename, json_object* jobj) {
    FILE *fp = fopen(filename, "w");
    if (!fp) return 1;

    size_t len = json_object_array_length(jobj);

    for (size_t i = 0; i < len; i++) {
        json_object *obj = json_object_array_get_idx(jobj, i);
        const char *pretty = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
        fprintf(fp, "%s\n", pretty);
    }

    fclose(fp);
    return 0;
}

int match_filter(DNS_Data item, const char* filter) {
    char buffer[256];
    strncpy(buffer, filter, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    char *token = strtok(buffer, " ");
    while (token) {
        char* key = token;
        char* value = strtok(NULL, " ");
        if (!value) break;

        if (strcmp(key, "type") == 0 && item.type != atoi(value)) return 1;
        if (strcmp(key, "class") == 0 && item.class != atoi(value)) return 1;
        if (strcmp(key, "name") == 0 && strcmp(item.name, value) != 0) return 1;

        token = strtok(NULL, " ");
    }
    return 0;
}

int parse_dns_name(const unsigned char *packet, int start, char *name) {
    int offset = start;
    int name_len = 0;
    int jumped = 0;
    int jump_offset = 0;

    while (1) {
        unsigned char len = packet[offset];
        if (len == 0) {
            // End of name
            if (!jumped) offset++;
            break;
        }
        if ((len & 0xC0) == 0xC0) { // Compression pointer
            if (!jumped) jump_offset = offset + 2;
            offset = ((len & 0x3F) << 8) | packet[offset + 1];
            jumped = 1;
            continue;
        }
        offset++;
        for (int i = 0; i < len; i++) {
            name[name_len++] = packet[offset++];
        }
        name[name_len++] = '.';
    }
    if (name_len > 0) name[name_len - 1] = '\0'; // Remove trailing dot
    else name[0] = '\0';

    return jumped ? jump_offset : offset;
}

size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    return size * nmemb;  // ignore data
}

void packet_handler(unsigned char* user, const struct pcap_pkthdr* header, const unsigned char* packet) {
    if (max_count != -1 && passed_count >= max_count) {
        pcap_breakloop(handle);
        return;
    }

    // parse headers
    int start = 14; // Ethernet
    int ihl = (packet[start] & 0x0F) * 4;
    int protocol = packet[start + 9];

    // ip addrs
    struct in_addr src_ip, dst_ip;
    memcpy(&src_ip.s_addr, &packet[start + 12], 4);
    memcpy(&dst_ip.s_addr, &packet[start + 16], 4);
    char* srcIP = inet_ntoa(src_ip);
    char* dstIP = inet_ntoa(dst_ip);

    start += ihl;

    // get ports
    int srcPort = 0, dstPort = 0;
    if (protocol == 6 || protocol == 17) {
        srcPort = bytesToInt(2, packet[start], packet[start+1]);
        dstPort = bytesToInt(2, packet[start+2], packet[start+3]);
    }

    if (!(protocol == 17 && (srcPort == port || dstPort == port))) return;

    start += (protocol == 6) ? 20 : 8; // TCP/UDP headers

    int id = bytesToInt(2, packet[start], packet[start+1]);
    int flags = bytesToInt(2, packet[start+2], packet[start+3]);
    int qdcount = bytesToInt(2, packet[start+4], packet[start+5]);
    int ancount = bytesToInt(2, packet[start+6], packet[start+7]);
    int nscount = bytesToInt(2, packet[start+8], packet[start+9]);
    int arcount = bytesToInt(2, packet[start+10], packet[start+11]);

    start += 12;

    // create json datas
    json_object* json_data = json_object_new_object();

    json_object_object_add(json_data, "packet_length", json_object_new_int(header->len));
    json_object_object_add(json_data, "srcIP", json_object_new_string(srcIP));
    json_object_object_add(json_data, "srcPort", json_object_new_int(srcPort));
    json_object_object_add(json_data, "dstIP", json_object_new_string(dstIP));
    json_object_object_add(json_data, "dstPort", json_object_new_int(dstPort));
    json_object_object_add(json_data, "id", json_object_new_int(id));
    json_object_object_add(json_data, "questions_count", json_object_new_int(qdcount));
    json_object_object_add(json_data, "answers_count", json_object_new_int(ancount));

    // parse dns request

    json_object* answers = json_object_new_object();
    json_object* atypes = json_object_new_array();
    json_object* anames = json_object_new_array();
    json_object* aclasses = json_object_new_array();

    json_object* questions = json_object_new_object();
    json_object* qtypes = json_object_new_array();
    json_object* qnames = json_object_new_array();
    json_object* qclasses = json_object_new_array();

    DNS_Data data[qdcount];

    for (int i = 0; i < qdcount; i++) {
        char qname[256] = {0};
        int next = parse_dns_name(packet, start, qname);
        start = next;

        // get qtype and qclass
        int qtype = bytesToInt(2, packet[start], packet[start+1]);
        int qclass = bytesToInt(2, packet[start+2], packet[start+3]);

        start += 4;

        memcpy(data[i].name, qname, strlen(qname));
        data[i].type = qtype;
        data[i].class = qclass;

        json_object_array_add(qtypes, json_object_new_int(qtype));
        json_object_array_add(qclasses, json_object_new_int(qclass));
        json_object_array_add(qnames, json_object_new_string(qname));

        if (dns_filters && !match_filter(data[i], dns_filters)) {
            json_object_put(json_data);
            return;
        }
    }

    for (int i = 0; i < ancount; i++) {
        start += 2;

        int atype = bytesToInt(2, packet[start], packet[start+1]);
        int aclass = bytesToInt(2, packet[start+2], packet[start+3]);
        int ttl = bytesToInt(4, packet[start+4], packet[start+5], packet[start+6], packet[start+7]);
        int length = bytesToInt(2, packet[start+8], packet[start+9]);

        start += 10;

        char *sname = malloc(length + 1);
        if (!sname) {
            fprintf(stderr, "Memory allocation failed\n");
            return;
        }

        memcpy(sname, packet + start, length);
        sname[length] = '\0';

        start += length;

        printf("%d\n", length);

        json_object_array_add(atypes, json_object_new_int(atype));
        json_object_array_add(aclasses, json_object_new_int(aclass));
        json_object_array_add(anames, json_object_new_string(sname));
    }

    json_object_object_add(questions, "types", qtypes);
    json_object_object_add(questions, "names", qnames);
    json_object_object_add(questions, "classes", qclasses);

    json_object_object_add(answers, "types", atypes);
    json_object_object_add(answers, "names", anames);
    json_object_object_add(answers, "classes", aclasses);

    json_object_object_add(json_data, "questions", questions);
    json_object_object_add(json_data, "answers", answers);

    if (jarray)
        json_object_array_add(jarray, json_data);

    // print data
    print_middle(table);
    print_ln(table, itos(header->len), srcIP, itos(srcPort), dstIP, itos(dstPort), itos(id), itos(qdcount), itos(ancount));

    // dump to file
    if (dumper) {
        pcap_dump((unsigned char*)dumper, header, packet);
    }

    if (db) {
        char sql[512];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO data (packet_length, srcIP, srcPort, dstIP, dstPort) VALUES (%d, '%s', %d, '%s', %d);",
                 header->len, srcIP, srcPort, dstIP, dstPort);
        sqlite3_exec(db, sql, 0, 0, NULL);
    }

    // make request to server
    if (server_endpoint_url) {
        CURL *curl;
        CURLcode res;

        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl = curl_easy_init();
        struct curl_slist *headers = NULL;

        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, server_endpoint_url);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

            headers = curl_slist_append(headers, "Content-Type: application/json");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

            char* data = json_object_to_json_string(json_data);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(data));

            res = curl_easy_perform(curl);

            if (res != CURLE_OK)
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

            curl_easy_cleanup(curl);
        }

        // clean up
        curl_global_cleanup();
    }

    passed_count++;
}

int main(int argc, char* argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* device = pcap_lookupdev(errbuf);

    if (!device) {
        fprintf(stderr, "No device found: %s\n", errbuf);
        return 1;
    }

    char* output = NULL, *filter_exp = NULL, *config_file = NULL, *json_file = NULL, *db_file = NULL, *url = NULL;
    int length = 65535, opt;

    while ((opt = getopt(argc, argv, "w:u:l:s:c:f:d:a:p:h")) != -1) {
        switch (opt) {
            case 'w':
                if (ends_with(optarg, ".json") || ends_with(optarg, ".jsonl")) json_file = optarg;
                else if (ends_with(optarg, ".db")) db_file = optarg;
                else output = optarg;
                break;
            case 'l': length = atoi(optarg); break;
            case 'c': max_count = atoi(optarg); break;
            case 'f': filter_exp = optarg; break;
            case 'd': config_file = optarg; break;
            case 'a': dns_filters = optarg; break;
            case 'p': port = atoi(optarg); break;
            case 'u': url = optarg; break;
            case 's': server_endpoint_url = optarg; break;
            case 'h':
                printf("Usage: %s [options]\n", argv[0]);
                return 0;
            default: return 1;
        }
    }

    handle = pcap_open_live(device, length, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }

    if (json_file) jarray = json_object_new_array();

    if (url) {
        CURL *curl;
        FILE *fp;
        CURLcode res;

        const char *outfilename = "output.json";

        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl = curl_easy_init();

        if (curl) {
            fp = fopen(outfilename, "wb");
            if (!fp) {
                perror("fopen");
                return 1;
            }

            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);

            res = curl_easy_perform(curl);

            if (res != CURLE_OK)
                fprintf(stderr, "Download failed: %s\n", curl_easy_strerror(res));
            else
                printf("File downloaded successfully to '%s'\n", outfilename);

            fclose(fp);
            curl_easy_cleanup(curl);
        }

        curl_global_cleanup();


        config_file = outfilename;
    }

    if (config_file) {
        json_object *json = readJsonFromFile(config_file);

        if (json) {
            json_object *v;
            if (json_object_object_get_ex(json, "dns_filter", &v)) dns_filters = strdup(json_object_get_string(v));
            if (json_object_object_get_ex(json, "filter", &v)) filter_exp = strdup(json_object_get_string(v));
            if (json_object_object_get_ex(json, "output", &v)) output = strdup(json_object_get_string(v));
            if (json_object_object_get_ex(json, "count", &v)) max_count = json_object_get_int(v);
            if (json_object_object_get_ex(json, "server_url", &v)) server_endpoint_url = strdup(json_object_get_string(v));
            json_object_put(json);
        }
    }

    if (filter_exp) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
            pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Failed to apply filter: %s\n", pcap_geterr(handle));
            return 1;
        }
        pcap_freecode(&fp);
    }

    if (output) {
        dumper = pcap_dump_open(handle, output);
        if (!dumper) {
            fprintf(stderr, "Could not open dump file: %s\n", pcap_geterr(handle));
            return 1;
        }
    }

    if (db_file) {
        if (sqlite3_open(db_file, &db) != SQLITE_OK) {
            fprintf(stderr, "Could not open DB: %s\n", sqlite3_errmsg(db));
            return 1;
        }

        const char *sql = "CREATE TABLE IF NOT EXISTS data ("
                          "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                          "packet_length INTEGER, "
                          "srcIP TEXT, srcPort INTEGER, dstIP TEXT, dstPort INTEGER);";
        sqlite3_exec(db, sql, 0, 0, NULL);
    }

    int widths[] = {13, 15, 11, 15, 16, 5, 18, 16};
    table = init_table(8, widths, 1);
    print_start(table);
    print_ln(table, "Packet Length", "source ip", "source port", "destination ip", "destination port", "ID", "Questions", "Answers");

    pcap_loop(handle, 0, packet_handler, NULL);
    print_end(table);

    if (jarray && json_file) writeJsonToFile(json_file, jarray);
    if (jarray) json_object_put(jarray);
    if (dumper) pcap_dump_close(dumper);
    if (db) sqlite3_close(db);
    if (table) {
        free(table);
    }

    pcap_close(handle);
    return 0;
}
