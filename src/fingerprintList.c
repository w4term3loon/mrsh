#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../header/fingerprintList.h"
#include "../header/helper.h"
#include "../header/util.h"

#define MAX_DIGEST_LENGTH \
    ((size_t)FINGERPRINT_NAME_MAX + 64U + \
     (size_t)MAX_FILTER * FILTERSIZE * 2U)
#define INITIAL_LINE_CAPACITY 4096U
#define READ_EOF 1

static void clear_fingerprint_list(FINGERPRINT_LIST *fpl)
{
    FINGERPRINT *node;

    if (fpl == NULL) {
        return;
    }
    node = fpl->list;
    while (node != NULL) {
        FINGERPRINT *next = node->next;
        node->next = NULL;
        (void)fingerprint_destroy(node);
        node = next;
    }
    fpl->list = NULL;
    fpl->last_element = NULL;
    fpl->size = 0U;
}

FINGERPRINT_LIST *init_empty_fingerprintList(void)
{
    return calloc(1U, sizeof(FINGERPRINT_LIST));
}

FINGERPRINT_LIST *init_fingerprintList_for_ListFile(const char *filename)
{
    FINGERPRINT_LIST *fpl;
    FILE *file;
    uint64_t file_size;
    int status;

    file = getFileHandle(filename);
    if (file == NULL) {
        return NULL;
    }
    status = find_file_size(file, &file_size);
    if (status != MRSH_OK ||
        file_size > (uint64_t)FINGERPRINT_LIST_MAX_BYTES) {
        (void)fclose(file);
        return NULL;
    }
    fpl = init_empty_fingerprintList();
    if (fpl == NULL) {
        (void)fclose(file);
        return NULL;
    }

    status = read_fingerprint_file(fpl, file);
    if (fclose(file) != 0 && status == MRSH_OK) {
        status = MRSH_ERR_IO;
    }
    if (status != MRSH_OK) {
        (void)fingerprintList_destroy(fpl);
        return NULL;
    }
    return fpl;
}

int fingerprintList_destroy(FINGERPRINT_LIST *fpl)
{
    if (fpl == NULL) {
        return MRSH_OK;
    }
    clear_fingerprint_list(fpl);
    free(fpl);
    return MRSH_OK;
}

int add_new_fingerprint(FINGERPRINT_LIST *fpl, FINGERPRINT *fp)
{
    if (fpl == NULL || fp == NULL || fp->next != NULL) {
        return MRSH_ERR_INVALID;
    }
    if ((fpl->list == NULL) != (fpl->last_element == NULL) ||
        (fpl->list == NULL) != (fpl->size == 0U) ||
        (fpl->last_element != NULL && fpl->last_element->next != NULL)) {
        return MRSH_ERR_INVALID;
    }
    if (fpl->size >= (size_t)FINGERPRINT_LIST_MAX_ENTRIES) {
        return MRSH_ERR_RANGE;
    }

    if (fpl->list == NULL) {
        fpl->list = fp;
    } else {
        fpl->last_element->next = fp;
    }
    fpl->last_element = fp;
    ++fpl->size;
    return MRSH_OK;
}

static int comparison_threshold(void)
{
    return mode == NULL ? 0 : mode->threshold;
}

static int account_comparison_output(const char *first_name,
                                     const char *second_name,
                                     size_t *output_bytes)
{
    const size_t line_overhead = 10U; /* two " | ", three digits, newline */
    size_t first_length;
    size_t second_length;
    size_t line_length;

    if (first_name == NULL || second_name == NULL || output_bytes == NULL ||
        *output_bytes > (size_t)MRSH_MAX_COMPARISON_OUTPUT_BYTES) {
        return MRSH_ERR_INVALID;
    }
    first_length = strnlen(first_name, FINGERPRINT_NAME_MAX);
    second_length = strnlen(second_name, FINGERPRINT_NAME_MAX);
    if (first_length >= FINGERPRINT_NAME_MAX ||
        second_length >= FINGERPRINT_NAME_MAX ||
        first_length > SIZE_MAX - second_length ||
        first_length + second_length > SIZE_MAX - line_overhead) {
        return MRSH_ERR_RANGE;
    }
    line_length = first_length + second_length + line_overhead;
    if (line_length > (size_t)MRSH_MAX_COMPARISON_OUTPUT_BYTES -
                          *output_bytes) {
        return MRSH_ERR_RANGE;
    }
    *output_bytes += line_length;
    return MRSH_OK;
}

static int allocate_comparison_scores(uint64_t candidate_count,
                                      uint8_t **scores_out)
{
    if (scores_out == NULL) {
        return MRSH_ERR_INVALID;
    }
    if (candidate_count > (uint64_t)SIZE_MAX) {
        return MRSH_ERR_RANGE;
    }
    *scores_out = NULL;
    if (candidate_count == 0U) {
        return MRSH_OK;
    }
    *scores_out = malloc((size_t)candidate_count * sizeof(**scores_out));
    return *scores_out == NULL ? MRSH_ERR_NOMEM : MRSH_OK;
}

static int account_comparison_work(const FINGERPRINT *first,
                                   const FINGERPRINT *second,
                                   uint64_t *candidate_count,
                                   uint64_t *bloom_work)
{
    uint64_t pair_work;
    int status;

    if (candidate_count == NULL || bloom_work == NULL) {
        return MRSH_ERR_INVALID;
    }
    if (*candidate_count >= MRSH_MAX_COMPARISON_CANDIDATES) {
        return MRSH_ERR_RANGE;
    }
    status = fingerprint_comparison_work(first, second, &pair_work);
    if (status != MRSH_OK) {
        return status;
    }
    if (*bloom_work > MRSH_MAX_BLOOM_COMPARISON_WORK - pair_work) {
        return MRSH_ERR_RANGE;
    }
    ++*candidate_count;
    *bloom_work += pair_work;
    return MRSH_OK;
}

int all_against_all_comparsion(const FINGERPRINT_LIST *fpl)
{
    const FINGERPRINT *first;
    uint64_t candidate_count = 0U;
    uint64_t bloom_work = 0U;
    uint8_t *scores = NULL;
    size_t score_index = 0U;
    size_t output_bytes = 0U;
    int status;

    if (fpl == NULL) {
        return MRSH_ERR_INVALID;
    }
    for (first = fpl->list; first != NULL; first = first->next) {
        const FINGERPRINT *second;
        for (second = first->next; second != NULL; second = second->next) {
            status = account_comparison_work(first, second,
                                             &candidate_count, &bloom_work);
            if (status != MRSH_OK) {
                return status;
            }
        }
    }
    status = allocate_comparison_scores(candidate_count, &scores);
    if (status != MRSH_OK) {
        return status;
    }
    for (first = fpl->list; first != NULL; first = first->next) {
        const FINGERPRINT *second;
        for (second = first->next; second != NULL; second = second->next) {
            int score = fingerprint_compare(first, second);
            if (score < 0) {
                free(scores);
                return score;
            }
            if (scores == NULL || score_index >= (size_t)candidate_count) {
                free(scores);
                return MRSH_ERR_INVALID;
            }
            scores[score_index++] = (uint8_t)score;
            if (score >= comparison_threshold()) {
                status = account_comparison_output(first->file_name,
                                                   second->file_name,
                                                   &output_bytes);
                if (status != MRSH_OK) {
                    free(scores);
                    return status;
                }
            }
        }
    }
    if (score_index != (size_t)candidate_count) {
        free(scores);
        return MRSH_ERR_INVALID;
    }
    score_index = 0U;
    for (first = fpl->list; first != NULL; first = first->next) {
        const FINGERPRINT *second;
        for (second = first->next; second != NULL; second = second->next) {
            int score;
            if (scores == NULL || score_index >= (size_t)candidate_count) {
                free(scores);
                return MRSH_ERR_INVALID;
            }
            score = (int)scores[score_index++];
            if (score >= comparison_threshold() &&
                printf("%s | %s | %.3i\n", first->file_name,
                       second->file_name, score) < 0) {
                free(scores);
                return MRSH_ERR_IO;
            }
        }
    }
    if (score_index != (size_t)candidate_count) {
        free(scores);
        return MRSH_ERR_INVALID;
    }
    free(scores);
    return MRSH_OK;
}

int fingerprint_list_comparsion(const FINGERPRINT_LIST *fpl1,
                                const FINGERPRINT_LIST *fpl2)
{
    const FINGERPRINT *first;
    uint64_t candidate_count = 0U;
    uint64_t bloom_work = 0U;
    uint8_t *scores = NULL;
    size_t score_index = 0U;
    size_t output_bytes = 0U;
    int status;

    if (fpl1 == NULL || fpl2 == NULL) {
        return MRSH_ERR_INVALID;
    }
    for (first = fpl1->list; first != NULL; first = first->next) {
        const FINGERPRINT *second;
        for (second = fpl2->list; second != NULL; second = second->next) {
            status = account_comparison_work(first, second,
                                             &candidate_count, &bloom_work);
            if (status != MRSH_OK) {
                return status;
            }
        }
    }
    status = allocate_comparison_scores(candidate_count, &scores);
    if (status != MRSH_OK) {
        return status;
    }
    for (first = fpl1->list; first != NULL; first = first->next) {
        const FINGERPRINT *second;
        for (second = fpl2->list; second != NULL; second = second->next) {
            int score = fingerprint_compare(first, second);
            if (score < 0) {
                free(scores);
                return score;
            }
            if (scores == NULL || score_index >= (size_t)candidate_count) {
                free(scores);
                return MRSH_ERR_INVALID;
            }
            scores[score_index++] = (uint8_t)score;
            if (score >= comparison_threshold()) {
                status = account_comparison_output(first->file_name,
                                                   second->file_name,
                                                   &output_bytes);
                if (status != MRSH_OK) {
                    free(scores);
                    return status;
                }
            }
        }
    }
    if (score_index != (size_t)candidate_count) {
        free(scores);
        return MRSH_ERR_INVALID;
    }
    score_index = 0U;
    for (first = fpl1->list; first != NULL; first = first->next) {
        const FINGERPRINT *second;
        for (second = fpl2->list; second != NULL; second = second->next) {
            int score;
            if (scores == NULL || score_index >= (size_t)candidate_count) {
                free(scores);
                return MRSH_ERR_INVALID;
            }
            score = (int)scores[score_index++];
            if (score >= comparison_threshold() &&
                printf("%s | %s | %.3i\n", first->file_name,
                       second->file_name, score) < 0) {
                free(scores);
                return MRSH_ERR_IO;
            }
        }
    }
    if (score_index != (size_t)candidate_count) {
        free(scores);
        return MRSH_ERR_INVALID;
    }
    free(scores);
    return MRSH_OK;
}

int fingerprint_against_list_comparison(const FINGERPRINT_LIST *fpl,
                                        const FINGERPRINT *fp)
{
    const FINGERPRINT *candidate;
    uint64_t candidate_count = 0U;
    uint64_t bloom_work = 0U;
    uint8_t *scores = NULL;
    size_t score_index = 0U;
    size_t output_bytes = 0U;
    int status;

    if (fpl == NULL || fp == NULL) {
        return MRSH_ERR_INVALID;
    }
    for (candidate = fpl->list; candidate != NULL; candidate = candidate->next) {
        status = account_comparison_work(candidate, fp, &candidate_count,
                                         &bloom_work);
        if (status != MRSH_OK) {
            return status;
        }
    }
    status = allocate_comparison_scores(candidate_count, &scores);
    if (status != MRSH_OK) {
        return status;
    }
    for (candidate = fpl->list; candidate != NULL; candidate = candidate->next) {
        int score = fingerprint_compare(candidate, fp);
        if (score < 0) {
            free(scores);
            return score;
        }
        if (scores == NULL || score_index >= (size_t)candidate_count) {
            free(scores);
            return MRSH_ERR_INVALID;
        }
        scores[score_index++] = (uint8_t)score;
        if (score >= comparison_threshold()) {
            status = account_comparison_output(candidate->file_name,
                                               fp->file_name,
                                               &output_bytes);
            if (status != MRSH_OK) {
                free(scores);
                return status;
            }
        }
    }
    if (score_index != (size_t)candidate_count) {
        free(scores);
        return MRSH_ERR_INVALID;
    }
    score_index = 0U;
    for (candidate = fpl->list; candidate != NULL; candidate = candidate->next) {
        int score;
        if (scores == NULL || score_index >= (size_t)candidate_count) {
            free(scores);
            return MRSH_ERR_INVALID;
        }
        score = (int)scores[score_index++];
        if (score >= comparison_threshold() &&
            printf("%s | %s | %.3i\n", candidate->file_name,
                   fp->file_name, score) < 0) {
            free(scores);
            return MRSH_ERR_IO;
        }
    }
    if (score_index != (size_t)candidate_count) {
        free(scores);
        return MRSH_ERR_INVALID;
    }
    free(scores);
    return MRSH_OK;
}

int print_fingerprintList(const FINGERPRINT_LIST *fpl)
{
    const FINGERPRINT *fingerprint;

    if (fpl == NULL) {
        return MRSH_ERR_INVALID;
    }
    for (fingerprint = fpl->list; fingerprint != NULL;
         fingerprint = fingerprint->next) {
        int status = fingerprint_fprint(stdout, fingerprint);
        if (status != MRSH_OK) {
            return status;
        }
    }
    return MRSH_OK;
}

static int parse_uint64_field(const char *text, size_t length,
                              uint64_t minimum, uint64_t maximum,
                              uint64_t *value_out)
{
    uint64_t value = 0U;
    size_t index;

    if (text == NULL || value_out == NULL || length == 0U) {
        return MRSH_ERR_FORMAT;
    }
    for (index = 0U; index < length; ++index) {
        uint64_t digit;
        if (text[index] < '0' || text[index] > '9') {
            return MRSH_ERR_FORMAT;
        }
        digit = (uint64_t)(unsigned int)(text[index] - '0');
        if (digit > maximum || value > (maximum - digit) / 10U) {
            return MRSH_ERR_RANGE;
        }
        value = value * 10U + digit;
    }
    if (value < minimum || value > maximum) {
        return MRSH_ERR_RANGE;
    }
    *value_out = value;
    return MRSH_OK;
}

static int decode_filter(const char *hex, BLOOMFILTER *filter)
{
    char terminated_hex[FILTERSIZE * 2U + 1U];

    memcpy(terminated_hex, hex, FILTERSIZE * 2U);
    terminated_hex[FILTERSIZE * 2U] = '\0';
    return convert_hex_binary(terminated_hex, filter);
}

int fingerprint_parse(const char *digest, FINGERPRINT **out)
{
    size_t separators[4];
    size_t length = 0U;
    size_t cursor;
    size_t separator_index;
    size_t hex_length;
    uint64_t filesize;
    uint64_t parsed_filter_count;
    uint64_t parsed_blocks_in_last_filter;
    uint32_t filter_count;
    uint32_t blocks_in_last_filter;
    FINGERPRINT *fingerprint;
    uint32_t filter_index;
    int status;

    if (digest == NULL || out == NULL) {
        return MRSH_ERR_INVALID;
    }
    *out = NULL;
    while (length <= MAX_DIGEST_LENGTH && digest[length] != '\0') {
        if (digest[length] == '\n' || digest[length] == '\r') {
            return MRSH_ERR_FORMAT;
        }
        ++length;
    }
    if (length > MAX_DIGEST_LENGTH) {
        return MRSH_ERR_RANGE;
    }

    cursor = length;
    for (separator_index = 4U; separator_index != 0U; --separator_index) {
        bool found = false;
        while (cursor != 0U) {
            --cursor;
            if (digest[cursor] == ':') {
                separators[separator_index - 1U] = cursor;
                found = true;
                break;
            }
        }
        if (!found) {
            return MRSH_ERR_FORMAT;
        }
    }
    if (separators[0] >= FINGERPRINT_NAME_MAX) {
        return MRSH_ERR_RANGE;
    }

    status = parse_uint64_field(digest + separators[0] + 1U,
                                separators[1] - separators[0] - 1U,
                                0U, UINT64_MAX, &filesize);
    if (status != MRSH_OK) {
        return status;
    }
    status = parse_uint64_field(digest + separators[1] + 1U,
                                separators[2] - separators[1] - 1U,
                                1U, MAX_FILTER, &parsed_filter_count);
    if (status != MRSH_OK) {
        return status;
    }
    status = parse_uint64_field(digest + separators[2] + 1U,
                                separators[3] - separators[2] - 1U,
                                0U, MAXBLOCKS,
                                &parsed_blocks_in_last_filter);
    if (status != MRSH_OK) {
        return status;
    }

    filter_count = (uint32_t)parsed_filter_count;
    blocks_in_last_filter = (uint32_t)parsed_blocks_in_last_filter;
    hex_length = length - separators[3] - 1U;
    if (hex_length != (size_t)filter_count * FILTERSIZE * 2U) {
        return MRSH_ERR_FORMAT;
    }

    fingerprint = init_empty_fingerprint();
    if (fingerprint == NULL) {
        return MRSH_ERR_NOMEM;
    }
    status = fingerprint_set_name_n(fingerprint, digest, separators[0]);
    if (status != MRSH_OK) {
        (void)fingerprint_destroy(fingerprint);
        return status;
    }
    fingerprint->filesize = filesize;

    for (filter_index = 0U; filter_index < filter_count; ++filter_index) {
        BLOOMFILTER *filter;

        if (filter_index == 0U) {
            filter = fingerprint->bf_list;
        } else {
            filter = init_empty_BF();
            if (filter == NULL) {
                (void)fingerprint_destroy(fingerprint);
                return MRSH_ERR_NOMEM;
            }
            status = add_new_bloomfilter(fingerprint, filter);
            if (status != MRSH_OK) {
                destroy_bf(filter);
                (void)fingerprint_destroy(fingerprint);
                return status;
            }
        }

        status = decode_filter(digest + separators[3] + 1U +
                                   (size_t)filter_index * FILTERSIZE * 2U,
                               filter);
        if (status != MRSH_OK) {
            (void)fingerprint_destroy(fingerprint);
            return status;
        }
        filter->amount_of_blocks =
            filter_index + 1U == filter_count ? blocks_in_last_filter : MAXBLOCKS;
    }

    *out = fingerprint;
    return MRSH_OK;
}

static int read_bounded_line(FILE *handle, char **line_in_out,
                             size_t *capacity_in_out, size_t *length_out,
                             size_t *bytes_read_out)
{
    char *line;
    size_t capacity;
    const size_t maximum_capacity = MAX_DIGEST_LENGTH + 1U;
    size_t length = 0U;
    size_t bytes_read = 0U;
    int character;

    if (handle == NULL || line_in_out == NULL || capacity_in_out == NULL ||
        length_out == NULL || bytes_read_out == NULL) {
        return MRSH_ERR_INVALID;
    }
    *length_out = 0U;
    *bytes_read_out = 0U;
    line = *line_in_out;
    capacity = *capacity_in_out;
    if (line == NULL) {
        capacity = MIN(INITIAL_LINE_CAPACITY, maximum_capacity);
        line = malloc(capacity);
        if (line == NULL) {
            return MRSH_ERR_NOMEM;
        }
        *line_in_out = line;
        *capacity_in_out = capacity;
    } else if (capacity < 2U || capacity > maximum_capacity) {
        return MRSH_ERR_INVALID;
    }

    while ((character = fgetc(handle)) != EOF) {
        ++bytes_read;
        if (character == '\n') {
            break;
        }
        if (character == 0) {
            *bytes_read_out = bytes_read;
            return MRSH_ERR_FORMAT;
        }
        if (length + 1U >= capacity) {
            size_t grown_capacity;
            char *grown_line;

            if (capacity == maximum_capacity) {
                *bytes_read_out = bytes_read;
                return MRSH_ERR_RANGE;
            }
            grown_capacity = capacity > maximum_capacity / 2U
                                 ? maximum_capacity
                                 : capacity * 2U;
            grown_line = realloc(line, grown_capacity);
            if (grown_line == NULL) {
                return MRSH_ERR_NOMEM;
            }
            line = grown_line;
            capacity = grown_capacity;
            *line_in_out = line;
            *capacity_in_out = capacity;
        }
        line[length++] = (char)character;
    }
    *bytes_read_out = bytes_read;
    if (character == EOF && ferror(handle) != 0) {
        return MRSH_ERR_IO;
    }
    if (character == EOF && length == 0U) {
        return READ_EOF;
    }
    if (length != 0U && line[length - 1U] == '\r') {
        --length;
    }
    line[length] = '\0';
    *length_out = length;
    return MRSH_OK;
}

static bool line_is_blank(const char *line, size_t length)
{
    size_t index;

    for (index = 0U; index < length; ++index) {
        if (!isspace((unsigned char)line[index])) {
            return false;
        }
    }
    return true;
}

int read_fingerprint_file(FINGERPRINT_LIST *fpl, FILE *handle)
{
    FINGERPRINT_LIST staged = {0};
    char *line = NULL;
    size_t line_capacity = 0U;
    size_t total_bytes = 0U;
    int status = MRSH_OK;

    if (fpl == NULL || handle == NULL) {
        return MRSH_ERR_INVALID;
    }
    for (;;) {
        size_t length = 0U;
        size_t bytes_read = 0U;
        FINGERPRINT *fingerprint;

        status = read_bounded_line(handle, &line, &line_capacity, &length,
                                   &bytes_read);
        if (bytes_read > (size_t)FINGERPRINT_LIST_MAX_BYTES - total_bytes) {
            status = MRSH_ERR_RANGE;
        } else {
            total_bytes += bytes_read;
        }
        if (status == READ_EOF) {
            status = MRSH_OK;
            break;
        }
        if (status != MRSH_OK) {
            break;
        }
        if (line_is_blank(line, length)) {
            continue;
        }

        status = fingerprint_parse(line, &fingerprint);
        if (status != MRSH_OK) {
            break;
        }
        status = add_new_fingerprint(&staged, fingerprint);
        if (status != MRSH_OK) {
            (void)fingerprint_destroy(fingerprint);
            break;
        }
    }
    free(line);

    if (status != MRSH_OK) {
        clear_fingerprint_list(&staged);
        return status;
    }
    if ((fpl->list == NULL) != (fpl->last_element == NULL) ||
        (fpl->list == NULL) != (fpl->size == 0U) ||
        (fpl->last_element != NULL && fpl->last_element->next != NULL)) {
        clear_fingerprint_list(&staged);
        return MRSH_ERR_INVALID;
    }
    if (fpl->size > (size_t)FINGERPRINT_LIST_MAX_ENTRIES ||
        staged.size > (size_t)FINGERPRINT_LIST_MAX_ENTRIES - fpl->size) {
        clear_fingerprint_list(&staged);
        return MRSH_ERR_RANGE;
    }
    if (staged.list != NULL) {
        if (fpl->list == NULL) {
            fpl->list = staged.list;
        } else {
            fpl->last_element->next = staged.list;
        }
        fpl->last_element = staged.last_element;
        fpl->size += staged.size;
    }
    return MRSH_OK;
}
