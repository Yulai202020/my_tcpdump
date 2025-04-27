// table.h
#ifndef TABLE_H
#define TABLE_H

typedef struct {
    int cols;
    int* widths;
    int style;
} table_t;

table_t* init_table(int cols, int* widths, int style);
void print_start(table_t* table);
void print_middle(table_t* table);
void print_end(table_t* table);
void print_separator(table_t *table, const char* start, const char* end, const char* sep, const char* up);
void print_ln(table_t* table, ...);

#endif // TABLE_H
