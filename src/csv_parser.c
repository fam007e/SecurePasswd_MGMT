#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "csv_parser.h"
#include "../lib/libcsv/csv.h"

// Temporary structure to hold data during parsing
struct CsvParseData {
    CsvData *data;
    CsvRow current_row;
};

// Callback for each field
static void field_cb(void *field, size_t field_len, void *data) {
    struct CsvParseData *parse_data = (struct CsvParseData *)data;
    CsvRow *row = &parse_data->current_row;

    row->num_fields++;
    row->fields = (char **)realloc(row->fields, row->num_fields * sizeof(char *));
    if (!row->fields) {
        // In a real-world scenario, you'd have better error handling
        exit(EXIT_FAILURE); 
    }

    row->fields[row->num_fields - 1] = (char *)malloc(field_len + 1);
    if (!row->fields[row->num_fields - 1]) {
        exit(EXIT_FAILURE);
    }
    memcpy(row->fields[row->num_fields - 1], field, field_len);
    row->fields[row->num_fields - 1][field_len] = '\0';
}

// Callback for each row
static void row_cb(int c, void *data) {
    (void)c; // Unused parameter
    struct CsvParseData *parse_data = (struct CsvParseData *)data;
    CsvData *csv_data = parse_data->data;

    csv_data->num_rows++;
    csv_data->rows = (CsvRow *)realloc(csv_data->rows, csv_data->num_rows * sizeof(CsvRow));
    if (!csv_data->rows) {
        exit(EXIT_FAILURE);
    }

    csv_data->rows[csv_data->num_rows - 1] = parse_data->current_row;

    // Reset current_row for the next line
    memset(&parse_data->current_row, 0, sizeof(CsvRow));
}

CsvData *parse_csv(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        return NULL;
    }

    struct csv_parser p;
    if (csv_init(&p, 0) != 0) {
        fclose(file);
        return NULL;
    }

    CsvData *data = (CsvData *)calloc(1, sizeof(CsvData));
    if (!data) {
        fclose(file);
        csv_free(&p);
        return NULL;
    }

    struct CsvParseData parse_data = { .data = data };
    memset(&parse_data.current_row, 0, sizeof(CsvRow));

    char buf[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buf, 1, sizeof(buf), file)) > 0) {
        if (csv_parse(&p, buf, bytes_read, field_cb, row_cb, &parse_data) != bytes_read) {
            // If csv_parse returns a different value, it indicates an error
            fprintf(stderr, "Error while parsing CSV file: %s\n", csv_strerror(csv_error(&p)));
            free_csv_data(data);
            csv_fini(&p, field_cb, row_cb, &parse_data);
            csv_free(&p);
            fclose(file);
            return NULL;
        }
    }

    csv_fini(&p, field_cb, row_cb, &parse_data);
    csv_free(&p);
    fclose(file);

    return data;
}

void free_csv_data(CsvData *data) {
    if (!data) {
        return;
    }

    for (int i = 0; i < data->num_rows; i++) {
        for (int j = 0; j < data->rows[i].num_fields; j++) {
            free(data->rows[i].fields[j]);
        }
        free(data->rows[i].fields);
    }
    free(data->rows);
    free(data);
}

int append_csv_row(const char *filename, const char **row, int num_fields) {
    FILE *file = fopen(filename, "a");
    if (!file) {
        return 0;
    }

    for (int i = 0; i < num_fields; i++) {
        // Use csv_fwrite2 to handle quoting automatically
        csv_fwrite2(file, row[i], strlen(row[i]), '"');
        if (i < num_fields - 1) {
            fputc(',', file);
        }
    }
    fputc('\n', file);

    fclose(file);
    return 1;
}

int write_csv_data(const char *filename, CsvData *data) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        return 0;
    }

    for (int i = 0; i < data->num_rows; i++) {
        for (int j = 0; j < data->rows[i].num_fields; j++) {
            csv_fwrite2(file, data->rows[i].fields[j], strlen(data->rows[i].fields[j]), '"');
            if (j < data->rows[i].num_fields - 1) {
                fputc(',', file);
            }
        }
        fputc('\n', file);
    }

    fclose(file);
    return 1;
}