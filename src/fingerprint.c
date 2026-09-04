#include <inttypes.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "../header/fingerprint.h"
#include "../header/hashing.h"

static size_t bounded_name_length(const char *name)
{
    size_t length = 0U;

    if (name == NULL) {
        return FINGERPRINT_NAME_MAX;
    }
    while (length < FINGERPRINT_NAME_MAX && name[length] != '\0') {
        ++length;
    }
    return length;
}

FINGERPRINT *init_empty_fingerprint(void)
{
    FINGERPRINT *fingerprint = calloc(1U, sizeof(FINGERPRINT));

    if (fingerprint == NULL) {
        return NULL;
    }
    fingerprint->bf_list = init_empty_BF();
    if (fingerprint->bf_list == NULL) {
        free(fingerprint);
        return NULL;
    }
    fingerprint->file_name = calloc(1U, 1U);
    if (fingerprint->file_name == NULL) {
        destroy_bf(fingerprint->bf_list);
        free(fingerprint);
        return NULL;
    }
    fingerprint->bf_list_last_element = fingerprint->bf_list;
    return fingerprint;
}

int fingerprint_set_name_n(FINGERPRINT *fp, const char *name, size_t length)
{
    char *copy;
    size_t index;

    if (fp == NULL || name == NULL) {
        return MRSH_ERR_INVALID;
    }
    if (length >= FINGERPRINT_NAME_MAX) {
        return MRSH_ERR_RANGE;
    }
    if (memchr(name, '\0', length) != NULL) {
        return MRSH_ERR_FORMAT;
    }
    for (index = 0U; index < length; ++index) {
        unsigned char byte = (unsigned char)name[index];
        if (byte < 0x20U || byte == 0x7fU) {
            return MRSH_ERR_FORMAT;
        }
    }

    copy = malloc(length + 1U);
    if (copy == NULL) {
        return MRSH_ERR_NOMEM;
    }
    memcpy(copy, name, length);
    copy[length] = '\0';
    free(fp->file_name);
    fp->file_name = copy;
    return MRSH_OK;
}

int fingerprint_set_name(FINGERPRINT *fp, const char *name)
{
    size_t length;

    if (name == NULL) {
        return MRSH_ERR_INVALID;
    }
    length = bounded_name_length(name);
    if (length >= FINGERPRINT_NAME_MAX) {
        return MRSH_ERR_RANGE;
    }
    return fingerprint_set_name_n(fp, name, length);
}

FINGERPRINT *init_fingerprint_for_file(FILE *handle, const char *filename)
{
    FINGERPRINT *fingerprint;
    int status;

    if (handle == NULL || filename == NULL) {
        if (handle != NULL) {
            (void)fclose(handle);
        }
        return NULL;
    }

    fingerprint = init_empty_fingerprint();
    if (fingerprint == NULL) {
        (void)fclose(handle);
        return NULL;
    }

    status = fingerprint_set_name(fingerprint, filename);
    if (status == MRSH_OK) {
        status = hashFileToFingerprint(fingerprint, handle);
    }
    if (fclose(handle) != 0 && status == MRSH_OK) {
        status = MRSH_ERR_IO;
    }
    if (status != MRSH_OK) {
        (void)fingerprint_destroy(fingerprint);
        return NULL;
    }
    return fingerprint;
}

int fingerprint_destroy(FINGERPRINT *fp)
{
    BLOOMFILTER *node;

    if (fp == NULL) {
        return MRSH_OK;
    }

    node = fp->bf_list;
    while (node != NULL) {
        BLOOMFILTER *next = node->next;
        destroy_bf(node);
        node = next;
    }
    free(fp->file_name);
    free(fp);
    return MRSH_OK;
}

static int fingerprint_filter_count_checked(const FINGERPRINT *fp,
                                            size_t *count_out)
{
    const BLOOMFILTER *node;
    const BLOOMFILTER *last = NULL;
    size_t count = 0U;

    if (fp == NULL || count_out == NULL || fp->bf_list == NULL ||
        fp->bf_list_last_element == NULL || fp->file_name == NULL ||
        bounded_name_length(fp->file_name) >= FINGERPRINT_NAME_MAX) {
        return MRSH_ERR_INVALID;
    }
    for (node = fp->bf_list; node != NULL; node = node->next) {
        if (count >= MAX_FILTER) {
            return MRSH_ERR_RANGE;
        }
        if (node->amount_of_blocks > MAXBLOCKS) {
            return MRSH_ERR_INVALID;
        }
        ++count;
        last = node;
    }
    if (last != fp->bf_list_last_element || count == 0U ||
        fp->amount_of_BF != (uint32_t)(count - 1U)) {
        return MRSH_ERR_INVALID;
    }
    *count_out = count;
    return MRSH_OK;
}

size_t fingerprint_filter_count(const FINGERPRINT *fp)
{
    size_t count = 0U;

    return fingerprint_filter_count_checked(fp, &count) == MRSH_OK ? count : 0U;
}

int fingerprint_comparison_work(const FINGERPRINT *fingerprint1,
                                const FINGERPRINT *fingerprint2,
                                uint64_t *work_out)
{
    size_t first_count;
    size_t second_count;
    uint64_t work;
    int status;

    if (work_out == NULL) {
        return MRSH_ERR_INVALID;
    }
    *work_out = 0U;
    status = fingerprint_filter_count_checked(fingerprint1, &first_count);
    if (status != MRSH_OK) {
        return status;
    }
    status = fingerprint_filter_count_checked(fingerprint2, &second_count);
    if (status != MRSH_OK) {
        return status;
    }
    if ((uint64_t)first_count > UINT64_MAX / (uint64_t)second_count) {
        return MRSH_ERR_RANGE;
    }
    work = (uint64_t)first_count * (uint64_t)second_count;
    if (work > MRSH_MAX_BLOOM_COMPARISON_WORK) {
        return MRSH_ERR_RANGE;
    }
    *work_out = work;
    return MRSH_OK;
}

int add_new_bloomfilter(FINGERPRINT *fp, BLOOMFILTER *bf)
{
    if (fp == NULL || bf == NULL || bf->next != NULL) {
        return MRSH_ERR_INVALID;
    }

    if (fp->bf_list == NULL) {
        fp->bf_list = bf;
        fp->bf_list_last_element = bf;
        fp->amount_of_BF = 0U;
        return MRSH_OK;
    }
    if (fp->bf_list_last_element == NULL) {
        return MRSH_ERR_INVALID;
    }
    if (fp->amount_of_BF >= MAX_FILTER - 1U) {
        return MRSH_ERR_RANGE;
    }

    fp->bf_list_last_element->next = bf;
    fp->bf_list_last_element = bf;
    ++fp->amount_of_BF;
    return MRSH_OK;
}

int add_hash_to_fingerprint(FINGERPRINT *fp, uint64 hash_value)
{
    BLOOMFILTER *last_filter;

    if (fp == NULL || fp->bf_list_last_element == NULL) {
        return MRSH_ERR_INVALID;
    }
    last_filter = fp->bf_list_last_element;

    if (last_filter->amount_of_blocks >= MAXBLOCKS) {
        BLOOMFILTER *new_filter = init_empty_BF();
        int status;

        if (new_filter == NULL) {
            return MRSH_ERR_NOMEM;
        }
        status = add_new_bloomfilter(fp, new_filter);
        if (status != MRSH_OK) {
            destroy_bf(new_filter);
            return status;
        }
        last_filter = new_filter;
    }
    return add_hash_to_bloomfilter(last_filter, hash_value);
}

FINGERPRINT *fingerprint_clone(const FINGERPRINT *source)
{
    FINGERPRINT *copy;
    const BLOOMFILTER *source_filter;
    BLOOMFILTER *destination_filter;
    size_t filter_index = 0U;

    if (source == NULL || source->bf_list == NULL || source->file_name == NULL) {
        return NULL;
    }

    copy = init_empty_fingerprint();
    if (copy == NULL) {
        return NULL;
    }
    if (fingerprint_set_name(copy, source->file_name) != MRSH_OK) {
        (void)fingerprint_destroy(copy);
        return NULL;
    }
    copy->filesize = source->filesize;
    destination_filter = copy->bf_list;

    for (source_filter = source->bf_list; source_filter != NULL;
         source_filter = source_filter->next) {
        if (filter_index >= MAX_FILTER) {
            (void)fingerprint_destroy(copy);
            return NULL;
        }
        if (filter_index != 0U) {
            destination_filter = init_empty_BF();
            if (destination_filter == NULL ||
                add_new_bloomfilter(copy, destination_filter) != MRSH_OK) {
                destroy_bf(destination_filter);
                (void)fingerprint_destroy(copy);
                return NULL;
            }
        }
        memcpy(destination_filter->array, source_filter->array,
               sizeof(destination_filter->array));
        destination_filter->amount_of_blocks = source_filter->amount_of_blocks;
        ++filter_index;
    }
    return copy;
}

static size_t comparable_filter_count(const FINGERPRINT *fingerprint)
{
    const BLOOMFILTER *filter;
    size_t count = 0U;

    if (fingerprint == NULL) {
        return 0U;
    }
    for (filter = fingerprint->bf_list; filter != NULL; filter = filter->next) {
        if (filter->amount_of_blocks < MINBLOCKS) {
            break;
        }
        ++count;
    }
    return count;
}

static bool fingerprint_content_equal(const FINGERPRINT *first,
                                      const FINGERPRINT *second)
{
    const BLOOMFILTER *first_filter;
    const BLOOMFILTER *second_filter;

    if (first->filesize != second->filesize) {
        return false;
    }
    first_filter = first->bf_list;
    second_filter = second->bf_list;
    while (first_filter != NULL && second_filter != NULL) {
        if (first_filter->amount_of_blocks != second_filter->amount_of_blocks ||
            memcmp(first_filter->array, second_filter->array,
                   sizeof(first_filter->array)) != 0) {
            return false;
        }
        first_filter = first_filter->next;
        second_filter = second_filter->next;
    }
    return first_filter == NULL && second_filter == NULL;
}

int fingerprint_compare(const FINGERPRINT *fingerprint1,
                        const FINGERPRINT *fingerprint2)
{
    const FINGERPRINT *larger;
    const FINGERPRINT *smaller;
    const BLOOMFILTER *filter;
    size_t first_count;
    size_t second_count;
    size_t denominator;
    uint64_t comparison_work;
    int status;
    int total_score = 0;

    status = fingerprint_comparison_work(fingerprint1, fingerprint2,
                                         &comparison_work);
    if (status != MRSH_OK) {
        return status;
    }
    (void)comparison_work;
    if (fingerprint_content_equal(fingerprint1, fingerprint2)) {
        return 100;
    }

    first_count = fingerprint_filter_count(fingerprint1);
    second_count = fingerprint_filter_count(fingerprint2);
    if (first_count >= second_count) {
        larger = fingerprint1;
        smaller = fingerprint2;
    } else {
        larger = fingerprint2;
        smaller = fingerprint1;
    }

    if (mode != NULL && mode->file_comparison) {
        denominator = comparable_filter_count(larger);
    } else {
        denominator = comparable_filter_count(smaller);
    }
    if (denominator == 0U) {
        return 0;
    }

    for (filter = smaller->bf_list; filter != NULL; filter = filter->next) {
        if (filter->amount_of_blocks < MINBLOCKS) {
            break;
        }
        int score = bloom_max_score(filter, larger);
        if (score < 0) {
            return score;
        }
        total_score += score;
    }
    return total_score / (int)denominator;
}

int bloom_max_score(const BLOOMFILTER *bf, const FINGERPRINT *fingerprint)
{
    const BLOOMFILTER *candidate;
    size_t filter_count;
    int status;
    int best_score = 0;
    int bits_in_first;

    if (bf == NULL || bf->amount_of_blocks > MAXBLOCKS) {
        return MRSH_ERR_INVALID;
    }
    status = fingerprint_filter_count_checked(fingerprint, &filter_count);
    if (status != MRSH_OK) {
        return status;
    }
    (void)filter_count;
    bits_in_first = (int)count_bits_set_to_one_of_BF(bf->array);

    for (candidate = fingerprint->bf_list; candidate != NULL;
         candidate = candidate->next) {
        int expected_minimum;
        int maximum;
        int threshold;
        int common;
        int score = 0;

        if (candidate->amount_of_blocks < MINBLOCKS) {
            break;
        }
        expected_minimum = (int)compute_e_min(
            bf->amount_of_blocks, candidate->amount_of_blocks);
        maximum = MIN(bits_in_first,
                      (int)count_bits_set_to_one_of_BF(candidate->array));
        threshold = (int)(0.3 * (double)(maximum - expected_minimum) +
                          (double)expected_minimum);
        common = (int)bloom_common_bits(candidate->array, bf->array);

        if (common >= threshold && maximum - threshold >= 1) {
            score = 100 * (common - threshold) / (maximum - threshold);
            score = MAX(0, MIN(score, 100));
        }
        if (score > best_score) {
            best_score = score;
            if (best_score == 100) {
                break;
            }
        }
    }
    return best_score;
}

double compute_e_min(uint32_t blocks_in_bf1, uint32_t blocks_in_bf2)
{
    double first = pow(PROBABILITY,
                       (double)SUBHASHES * (double)blocks_in_bf1);
    double second = pow(PROBABILITY,
                        (double)SUBHASHES * (double)blocks_in_bf2);
    double both = pow(PROBABILITY,
                      (double)SUBHASHES *
                          ((double)blocks_in_bf1 + (double)blocks_in_bf2));

    return (double)BLOOMFILTERBITSIZE * (1.0 - first - second + both);
}

int fingerprint_fprint(FILE *stream, const FINGERPRINT *fp)
{
    const BLOOMFILTER *filter;
    const BLOOMFILTER *last;
    size_t filter_count;
    size_t index;

    if (stream == NULL || fp == NULL || fp->bf_list == NULL ||
        fp->file_name == NULL ||
        bounded_name_length(fp->file_name) >= FINGERPRINT_NAME_MAX) {
        return MRSH_ERR_INVALID;
    }

    filter_count = fingerprint_filter_count(fp);
    if (filter_count == 0U || filter_count > MAX_FILTER) {
        return MRSH_ERR_RANGE;
    }
    last = fp->bf_list;
    while (last->next != NULL) {
        last = last->next;
    }

    if (fprintf(stream, "%s:%" PRIu64 ":%zu:%" PRIu32 ":",
                fp->file_name, fp->filesize, filter_count,
                last->amount_of_blocks) < 0) {
        return MRSH_ERR_IO;
    }
    for (filter = fp->bf_list; filter != NULL; filter = filter->next) {
        for (index = 0U; index < FILTERSIZE; ++index) {
            if (fprintf(stream, "%02X", filter->array[index]) < 0) {
                return MRSH_ERR_IO;
            }
        }
    }
    if (fputc('\n', stream) == EOF) {
        return MRSH_ERR_IO;
    }
    return MRSH_OK;
}

int print_fingerprint(const FINGERPRINT *fp)
{
    return fingerprint_fprint(stdout, fp);
}
