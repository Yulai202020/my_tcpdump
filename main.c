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

int max_count = -1;
int passed_count = 0;

char* itos(int value) {
    char* str = malloc(12);
    if (str) sprintf(str, "%d", value);
    return str;
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

void packet_handler(unsigned char* user, const pcap_pkthdr* header, const unsigned char* packet) {
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
    if (!(protocol == 17 && (srcPort == 53 || dstPort == 53))) {
        return;
    }

    // print table
    print_middle(table);

    if (srcPort > 0 && dstPort > 0) {
        print_ln(table, itos(header->len), srcIP, itos(srcPort), dstIP, itos(dstPort));
    } else {
        print_ln(table, itos(header->len), srcIP, "", dstIP, "");
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
        json_object_array_add(jarray, tmp);
    } if (db) {
        char *sql;
        sprintf(sql, "INSERT INTO data (packet_length, srcIP, srcPort, dstIP, dstPort) VALUES ('%d', '%s', '%d', '%s', '%d');", header->len, srcIP, srcPort, dstIP, dstPort);
        sqlite3_exec(db, sql, 0, 0, NULL);
    }

    // body

    int qr = packet[start] & 0x10000000;
    int opcode = packet[start] & 0x01111000;
    int aa = packet[start] & 0x00000100;
    int tc = packet[start] & 0x00000010;
    int rd = packet[start] & 0x00000001;

    start+=1;

    int ra = packet[start] & 0x10000000;
    int rcode = packet[start] & 0x00001111;

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

    while ((opt = getopt(argc, argv, "s:w:c:f:d:j:b:r:")) != -1) {
        switch (opt) {
            case 'w':
                output = optarg;
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
            case 'j':
                json_file = optarg;
                break;
            case 'b':
                db_file = optarg;
                break;
            default:
                printf("Unknown error\n");
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
            json_object* length_obj;
            json_object* output_obj;

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
        dumper = pcap_dump_open(handle, "capture.pcap");
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
    int widths[] = {13, 9, 11, 14, 16};

    table = init_table(5, widths, 1);

    print_start(table);
    print_ln(table, "Packet Length", "source ip", "source port", "destination ip", "destination port");

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