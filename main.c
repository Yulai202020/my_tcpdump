#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>

#include <json-c/json.h>
#include <pcap.h>
#include "table.h"

typedef struct bpf_program bpf_program;

pcap_dumper_t *dumper = NULL;
table_t* table;

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

json_object* readFromFile(char* filepath) {
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

void packet_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet) {
    if (dumper != NULL) {
        pcap_dump((unsigned char*)dumper, header, packet);
    }

    int start = 0;

    start += 14; // ethernet header skip

    int ihl = (packet[start] & 0x0f) * 4;
    int protocol = packet[start + 9];

    struct in_addr src_ip, dst_ip;
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

    print_middle(table);

    if (srcPort > 0 && dstPort > 0) {
        print_ln(table, itos(header->len), srcIP, itos(srcPort), dstIP, itos(dstPort));
    } else {
        print_ln(table, itos(header->len), srcIP, "", dstIP, "");
    }

    if (protocol == 17) {
        if (srcPort == 53 || dstPort == 53) {

        }
    }

    // body
}

int main(int argc, char* argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE]; // error buffer
    pcap_t* handle; // handler
    const char* device = NULL; // device

    char* output = NULL;
    char* filter_exp = NULL;
    char* config_file = NULL;
    int max_count = -1;
    int length = 0;
    int opt;

    while ((opt = getopt(argc, argv, "s:w:c:f:d:")) != -1) {
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
            default:
                printf("Unknown error\n");
        }
    }

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

    if (config_file != NULL) {
        json_object* json = readFromFile(config_file);

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

            if (json_object_object_get_ex(json, "length", &length_obj)) {
                length = json_object_get_int(length_obj);
            }

            json_object_put(json);
        } else {
            if (dumper) {
                pcap_dump_close(dumper);
            }
            pcap_close(handle);
            return 1;
        }
    } if (filter_exp != NULL) {
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
    }

    if (output != NULL) {
        dumper = pcap_dump_open(handle, "capture.pcap");
        if (!dumper) {
            fprintf(stderr, "Error opening output file: %s\n", pcap_geterr(handle));
            return 1;
        }
    }

    int widths[] = {13, 9, 11, 14, 16};

    table = init_table(5, widths, 1);

    print_start(table);
    print_ln(table, "Packet Length", "source ip", "source port", "destination ip", "destination port");

    if (pcap_loop(handle, max_count, packet_handler, (unsigned char *)dumper) < 0) {
        fprintf(stderr, "Error capturing packets: %s\n", pcap_geterr(handle));
        return 1;
    }

    print_end(table);

    // freeing
    free(table->widths);
    free(table);

    if (dumper) {
        pcap_dump_close(dumper);
    }
    pcap_close(handle);
    return 0;
}