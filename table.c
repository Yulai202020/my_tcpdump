#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

const char* global_styles[][4] = {
    {"+", "+", "+", "-"},
    {"color: red", "background: blue", "font-size: 16px"},
    {"border: 1px solid black", "padding: 10px", "margin: 5px"}
};

typedef struct {
    int cols;
    int style;
    int* widths;
} table_t;

table_t* init_table(int cols, int* widths, int style) {
    table_t* table = (table_t*)malloc(sizeof(table_t));
    if (!table) {
        fprintf(stderr, "Memory allocation failed for table.\n");
        exit(1);
    }

    table->cols = cols;
    table->style = style;
    table->widths = (int*)malloc(cols * sizeof(int));
    if (!table->widths) {
        fprintf(stderr, "Memory allocation failed for widths.\n");
        free(table);
        exit(1);
    }

    memcpy(table->widths, widths, cols * sizeof(int));

    return table;
}

void print_separator(table_t *table, const char* start, const char* end, const char* sep, const char* up) {
    printf("%s", start);
    for (int i = 0; i < table->cols; i++) {
        for (int j = 0; j < table->widths[i] + 2; j++) printf("%s", up);
        if (i != table->cols - 1) {
            printf("%s", sep);
        }
    }
    printf("%s\n", end);
}

void print_start(table_t *table) {
    if (table->style == 0) {
        print_separator(table, "+", "+", "+", "-");
    } else if (table->style == 1) {
        print_separator(table, "╔", "╗", "╦", "═");
    }
}

void print_middle(table_t *table) {
    if (table->style == 0) {
        print_separator(table, "+", "+", "+", "-");
    } else if (table->style == 1) {
        print_separator(table, "╠", "╣", "╬", "═");
    }
}

void print_end(table_t *table) {
    if (table->style == 0) {
        print_separator(table, "+", "+", "+", "-");
    } else if (table->style == 1) {
        print_separator(table, "╚", "╝", "╩", "═");
    }
}

void print_ln(table_t *table, ...) {
    va_list args;
    va_start(args, table);

    if (table->style == 0) {
        printf("|");
    } else if (table->style == 1) {
        printf("║");
    }

    for (int i = 0; i < table->cols; ++i) {
        char* val = va_arg(args, char*);
        printf(" ");
        printf("%-*.*s", table->widths[i], table->widths[i], val); // left align
        printf(" ");

        if (table->style == 0) {
            printf("|");
        } else if (table->style == 1) {
            printf("║");
        }
    }

    printf("\n");
    va_end(args);
}