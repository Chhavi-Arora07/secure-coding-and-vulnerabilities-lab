#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Vulnerable query & file export handler (CWE-89, CWE-22, CWE-134, CWE-401) */
void build_db_query_vuln(const char *filter_param, char *out_sql, size_t out_size) {
    /* CWE-89: Direct string concatenation into SQL query without parameterization */
    snprintf(out_sql, out_size,
             "SELECT id, title, status FROM tasks WHERE owner = '%s' AND deleted = 0;",
             filter_param);
}

int export_report_vuln(const char *filename, const char *audit_banner) {
    char filepath[256];
    /* CWE-22: Path traversal via unsanitized filename */
    snprintf(filepath, sizeof(filepath), "/var/app/exports/%s", filename);

    FILE *fp = fopen(filepath, "w");
    if (fp == NULL) {
        perror("fopen");
        return -1;
    }

    /* CWE-134: Externally controlled format string */
    fprintf(fp, audit_banner);
    fprintf(fp, "\nReport generated successfully.\n");

    /* CWE-401 / CWE-775: Missing fclose(fp) on early return or error path */
    if (strlen(filename) > 100) {
        return -2; /* File descriptor leaked */
    }

    fclose(fp);
    return 0;
}

int main(void) {
    char sql[512];
    build_db_query_vuln("alice' OR '1'='1", sql, sizeof(sql));
    printf("Constructed SQL: %s\n", sql);
    return 0;
}
