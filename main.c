#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <argtable3.h>

#include <json-c/json.h>
#include <pcap.h>
#include <sqlite3.h>
#include "table.h"

typedef struct bpf_program bpf_program;
typedef struct pcap_pkthdr pcap_pkthdr;
typedef struct in_addr in_addr;

pcap_t* handle = NULL;
pcap_dumper_t *dumper = NULL;

json_object *jarray = NULL;
sqlite3* db = NULL;
table_t* table;

char* dns_filters = NULL;
int max_count = -1;
int passed_count = 0;
int port = 53;

typedef struct {
    int type;
    int class;
    char* name;
} DNS_Data;

char* itos(int value) {
    char* str = malloc(12);
    if (str) sprintf(str, "%d", value);
    return str;
}

char** split_by_space(char* input, int* count) {
    char* temp = strdup(input);  // Duplicate input so original is unchanged
    char* token = strtok(temp, " ");
    int capacity = 10;
    int size = 0;

    char** result = malloc(capacity * sizeof(char*));
    if (!result) return NULL;

    while (token) {
        if (size >= capacity) {
            capacity *= 2;
            result = realloc(result, capacity * sizeof(char*));
        }
        result[size++] = strdup(token);  // Copy token
        token = strtok(NULL, " ");
    }

    free(temp);  // Free the duplicated string
    *count = size;
    return result;
}

bool ends_with(const char *str, const char *suffix) {
    if (!str || !suffix)
        return false;

    size_t len_str = strlen(str);
    size_t len_suffix = strlen(suffix);

    if (len_suffix > len_str)
        return false;

    // Compare the end of `str` with `suffix`
    return strncmp(str + len_str - len_suffix, suffix, len_suffix) == 0;
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
    if (!fp) {
        perror("Unable to open file");
        return NULL;
    }

    // Find file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    rewind(fp);

    // Allocate memory
    char *buffer = malloc(file_size + 1);
    if (!buffer) {
        perror("Unable to allocate buffer");
        fclose(fp);
        return NULL;
    }

    fread(buffer, 1, file_size, fp);
    buffer[file_size] = '\0';
    fclose(fp);

    json_object* parsed_json = json_tokener_parse(buffer);
    free(buffer);

    if (!parsed_json) {
        fprintf(stderr, "Error parsing JSON.\n");
        return NULL;
    }

    return parsed_json;
}

int writeJsonToFile(const char* filename, json_object* jobj) {
    FILE *fp = fopen(filename, "w");
    if (fp == NULL) {
        perror("Unable to open file");
        return 1;
    }

    size_t array_len = json_object_array_length(jarray);

    for (size_t i = 0; i < array_len; i++) {
        json_object *obj = json_object_array_get_idx(jarray, i);
        const char *json_str = json_object_to_json_string(obj);
        fprintf(fp, "%s\n", json_str);
    }

    fclose(fp);

    return 0;
}

bool isEqual(char* s1, char* s2) {
    return strcmp(s1, s2) == 0;
}

int match_filter(DNS_Data item, const char* filter) {
    char buffer[256];
    strcpy(buffer, filter);

    char* token = strtok(buffer, " ");
    while (token) {
        char* key = token;
        token = strtok(NULL, " ");
        if (!token) break;

        char* value = token;
        token = strtok(NULL, " ");

        if (strcmp(key, "type") == 0 && item.type == atoi(value)) {
            return 0;
        } else if (strcmp(key, "class") == 0 && item.class == atoi(value)) {
            return 0;
        } else if (strcmp(key, "name") == 0 && strcmp(item.name, value) == 0) {
            return 0;
        }
    }

    return 1;
}

void packet_handler(unsigned char* user, const pcap_pkthdr* header, const unsigned char* packet) {
    size_t len = header->len;

    if (passed_count >= max_count && max_count != -1) {
        pcap_breakloop(handle);
        return;
    }

    // parse packet
    int start = 0;

    start += 14; // ethernet header skip

    int ihl = (packet[start] & 0x0f) * 4;
    int protocol = packet[start + 9];

    in_addr src_ip, dst_ip;
    memcpy(&src_ip.s_addr, &packet[start + 12], 4);
    memcpy(&dst_ip.s_addr, &packet[start + 16], 4);
    char* srcIP = inet_ntoa(src_ip);
    char* dstIP = inet_ntoa(dst_ip);

    start += ihl; // ip header skip

    int srcPort, dstPort;

    if (protocol == 6 || protocol == 17) {
        srcPort = bytesToInt(2, packet[start], packet[start+1]);
        dstPort = bytesToInt(2, packet[start+2], packet[start+3]);
    }

    if (protocol == 6) { // tcp
        start += 20;
    } else if (protocol == 17) {
        start += 8;
    }

    // check is dns
    if (!(protocol == 17 && (srcPort == port || dstPort == port))) {
        return;
    }

    // body

    int id = bytesToInt(2, packet[start], packet[start + 1]);

    start+=2;

    int qr = packet[start] & 0x10000000;
    int opcode = packet[start] & 0x01111000;
    int aa = packet[start] & 0x00000100;
    int tc = packet[start] & 0x00000010;
    int rd = packet[start] & 0x00000001;

    start+=1;

    int ra = packet[start] & 0x10000000;
    int rcode = packet[start] & 0x00001111;

    start+=1;

    int qdcount = bytesToInt(2, packet[start], packet[start + 1]);
    int ancount = bytesToInt(2, packet[start + 2], packet[start + 3]);
    int nscount = bytesToInt(2, packet[start + 4], packet[start + 5]);
    int arcount = bytesToInt(2, packet[start + 6], packet[start + 7]);

    start+=8;

    DNS_Data data[qdcount];

    // questions
    for (int i = 0; i < qdcount; i++) {
        int length = 0;
        unsigned char tmp = packet[start];

        for (; tmp != NULL; length++) {
            tmp = packet[start + length + 1];
        }

        printf("%d\n", length);

        char* name = malloc((length + 1) * sizeof(char));

        for (int k = 0; k < length; k++) {
            name[k] = (char) packet[start + k];
        }

        name[length] = '\0';

        start += 1; // skip name

        int qtype = bytesToInt(2, packet[start], packet[start+1]);
        int qclass = bytesToInt(2, packet[start+2], packet[start+3]);

        start += 4;

        data[i].name = name;
        data[i].type = qtype;
        data[i].class = qclass;

        free(name);

        if (dns_filters && !match_filter(data[i], dns_filters)) {
            return;
        }
    }

    // answers
    for (int i = 0; i < ancount; i++) {
        start += 10;
        int datalen = bytesToInt(2, packet[start], packet[start + 1]);
        start += datalen;
    }

    for (int i = 0; i < nscount; i++) {}

    for (int i = 0; i < arcount; i++) {}

    // print table
    print_middle(table);

    if (srcPort > 0 && dstPort > 0) {
        print_ln(table, itos(header->len), srcIP, itos(srcPort), dstIP, itos(dstPort), itos(id), itos(qdcount), itos(ancount));
    } else {
        print_ln(table, itos(header->len), srcIP, "", dstIP, "", itos(id), itos(qdcount), itos(ancount));
    }

    // dumping

    if (dumper) {
        pcap_dump((unsigned char*)dumper, header, packet);
    } if (jarray) {
        json_object* tmp = json_object_new_object();
        json_object_object_add(tmp, "packet_length", json_object_new_int(header->len));
        json_object_object_add(tmp, "srcIP", json_object_new_string(srcIP));
        json_object_object_add(tmp, "srcPort", json_object_new_int(srcPort));
        json_object_object_add(tmp, "dstIP", json_object_new_string(dstIP));
        json_object_object_add(tmp, "dstPort", json_object_new_int(dstPort));
        json_object_object_add(tmp, "id", json_object_new_int(id));
        json_object_object_add(tmp, "question_count", json_object_new_int(qdcount));
        json_object_object_add(tmp, "answer_count", json_object_new_int(ancount));
        json_object_array_add(jarray, tmp);
    } if (db) {
        char *sql;
        sprintf(sql, "INSERT INTO data (packet_length, srcIP, srcPort, dstIP, dstPort) VALUES ('%d', '%s', '%d', '%s', '%d');", header->len, srcIP, srcPort, dstIP, dstPort);
        sqlite3_exec(db, sql, 0, 0, NULL);
    }

    passed_count++;
}

int main(int argc, char* argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE]; // error buffer
    const char* device = NULL; // device

    char* output = NULL;
    char* filter_exp = NULL;
    char* config_file = NULL;
    char* json_file = NULL;
    char* db_file = NULL;
    int length = 0;
    int opt;

    while ((opt = getopt(argc, argv, "w:s:c:f:d:a:p:h")) != -1) {
        switch (opt) {
            case 'w':
                if (ends_with(optarg, ".json") || ends_with(optarg, ".jsonl")) {
                    json_file = optarg;
                } else if (ends_with(optarg, ".db")) {
                    db_file = optarg;
                } else { // pcap
                    output = optarg;
                } 
                break;
            case 's':
                length = atoi(optarg);
                break;
            case 'c':
                max_count = atoi(optarg);
                break;
            case 'f':
                filter_exp = optarg;
                break;
            case 'd':
                config_file = optarg;
                break;
            case 'a':
                dns_filters = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'h':
                // print help
                printf("Usage: %s [options]\n\n", argv[0]);
                printf("Program to capture dns packets\n\n");
                printf("Options:\n");
                printf("-w  Write captured data to file\n");
                printf("-c  Sets max count of captured packets\n");
                printf("-d  Get data from config file\n");
                printf("-f  Sets filters\n");
                printf("-a  Sets dns filters\n");
                printf("-p  Specify dns port\n");
                printf("-h  Get help\n");
                return 0;
                break;
            default:
                return 1;
        }
    }

    // init pcap
    device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        fprintf(stderr, "Device not found: %s\n", errbuf);
        return 1;
    }

    handle = pcap_open_live(device, length, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 1;
    }

    // init flags
    if (json_file) {
        jarray = json_object_new_array();
    } if (config_file) {
        json_object* json = readJsonFromFile(config_file);

        if (json) {
            json_object* filter_obj;
            json_object* count_obj;
            json_object* dns_filter_obj;
            json_object* output_obj;

            if (json_object_object_get_ex(json, "dns_filter", &dns_filter_obj)) {
                dns_filters = json_object_get_string(dns_filter_obj);
            }

            if (json_object_object_get_ex(json, "filter", &filter_obj)) {
                filter_exp = json_object_get_string(filter_obj);
            }

            if (json_object_object_get_ex(json, "output", &output_obj)) {
                output = json_object_get_string(output_obj);
            }

            if (json_object_object_get_ex(json, "count", &count_obj)) {
                max_count = json_object_get_int(count_obj);
            }

            json_object_put(json);
        } else {
            if (dumper) {
                pcap_dump_close(dumper);
            }
            pcap_close(handle);
            return 1;
        }
    } if (filter_exp) {
        bpf_program fp;

        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return 1;
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return 1;
        }

        pcap_freecode(&fp);
    } if (output) {
        dumper = pcap_dump_open(handle, output);
        if (!dumper) {
            fprintf(stderr, "Error opening output file: %s\n", pcap_geterr(handle));
            return 1;
        }
    } if (db_file) {
        int rc = sqlite3_open(db_file, &db);
        char *err_msg = NULL;

        if (rc != SQLITE_OK) {
            fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            return 1;
        }

        // init db

        const char *sql = "CREATE TABLE IF NOT EXISTS data (id INTEGER PRIMARY KEY, packet_length INTEGER, srcIP TEXT, srcPort INTEGER. dstIP TEXT, dstPort INTEGER);";

        rc = sqlite3_exec(db, sql, 0, 0, &err_msg);

        if (rc != SQLITE_OK) {
            fprintf(stderr, "SQL error: %s\n", err_msg);
            sqlite3_free(err_msg);
        } else {
            printf("Table created and data inserted successfully.\n");
        }
    }

    // init table
    int widths[] = {13, 9, 11, 14, 16, 5, 18, 16};

    table = init_table(8, widths, 1);

    print_start(table);
    print_ln(table, "Packet Length", "source ip", "source port", "destination ip", "destination port", "ID", "Count of Questions", "Count of Answers");

    if (pcap_loop(handle, 0, packet_handler, (unsigned char *)dumper) == -1) {
        fprintf(stderr, "Error capturing packets: %s\n", pcap_geterr(handle));
        return 1;
    }

    print_end(table);

    // freeing
    if (jarray) {
        writeJsonToFile(json_file, jarray);
        json_object_put(jarray);
    }

    if (dumper) pcap_dump_close(dumper);
    if (table) {
        free(table->widths);
        free(table);
    }
    if (db) sqlite3_close(db);
    
    pcap_close(handle);
    return 0;
}