#ifndef CSV_PARSER_H
#define CSV_PARSER_H

#include <stdio.h>

// Represents a single CSV record (row)
typedef struct CsvRow {
    char **fields;
    int num_fields;
} CsvRow;

// Represents a whole CSV file
typedef struct CsvData {
    CsvRow *rows;
    int num_rows;
} CsvData;

/**
 * @brief Parses a CSV file into a CsvData struct.
 *
 * This function reads an entire CSV file and parses it into a structured format.
 * It handles quoted fields and commas within fields.
 *
 * @param filename The path to the CSV file.
 * @return A pointer to a CsvData struct, or NULL on failure.
 *         The caller is responsible for freeing the returned struct using free_csv_data().
 */
CsvData *parse_csv(const char *filename);

/**
 * @brief Frees the memory allocated for a CsvData struct.
 *
 * @param data A pointer to the CsvData struct to be freed.
 */
void free_csv_data(CsvData *data);

/**
 * @brief Appends a row to a CSV file.
 *
 * This function appends a new row to the specified CSV file.
 * It properly handles quoting of fields.
 *
 * @param filename The path to the CSV file.
 * @param row An array of strings representing the fields of the row.
 * @param num_fields The number of fields in the row.
 * @return 1 on success, 0 on failure.
 */
int append_csv_row(const char *filename, const char **row, int num_fields);

/**
 * @brief Writes a CsvData struct to a file.
 *
 * This function writes the entire CsvData struct to the specified file,
 * overwriting it if it already exists.
 *
 * @param filename The path to the CSV file.
 * @param data A pointer to the CsvData struct to be written.
 * @return 1 on success, 0 on failure.
 */
int write_csv_data(const char *filename, CsvData *data);

#endif // CSV_PARSER_H
