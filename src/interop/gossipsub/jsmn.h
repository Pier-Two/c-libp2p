/*
 * MIT License
 * -----------
 * Copyright (c) 2010 Serge Zaitsev
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef JSMN_H
#define JSMN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    JSMN_UNDEFINED = 0,
    JSMN_OBJECT = 1,
    JSMN_ARRAY = 2,
    JSMN_STRING = 3,
    JSMN_PRIMITIVE = 4
} jsmntype_t;

enum jsmnerr
{
    JSMN_ERROR_NOMEM = -1,
    JSMN_ERROR_INVAL = -2,
    JSMN_ERROR_PART = -3
};

typedef struct
{
    jsmntype_t type;
    int start;
    int end;
    int size;
    int parent;
} jsmntok_t;

typedef struct
{
    unsigned int pos;
    unsigned int toknext;
    int toksuper;
} jsmn_parser;

void jsmn_init(jsmn_parser *parser);
int jsmn_parse(jsmn_parser *parser, const char *js, size_t len, jsmntok_t *tokens, unsigned int num_tokens);

#ifdef __cplusplus
}
#endif

#ifdef JSMN_IMPLEMENTATION

#include <ctype.h>

static jsmntok_t *jsmn_alloc_token(jsmn_parser *parser, jsmntok_t *tokens, size_t num_tokens)
{
    if (parser->toknext >= num_tokens)
        return NULL;
    jsmntok_t *tok = &tokens[parser->toknext++];
    tok->type = JSMN_UNDEFINED;
    tok->start = tok->end = -1;
    tok->size = 0;
    tok->parent = -1;
    return tok;
}

static void jsmn_fill_token(jsmntok_t *token, jsmntype_t type, int start, int end)
{
    token->type = type;
    token->start = start;
    token->end = end;
    token->size = 0;
}

static int jsmn_parse_primitive(jsmn_parser *parser, const char *js, size_t len, jsmntok_t *tokens, size_t num_tokens)
{
    int start = parser->pos;
    for (; parser->pos < len; parser->pos++)
    {
        switch (js[parser->pos])
        {
            case '\t':
            case '\r':
            case '\n':
            case ' ':
            case ',':
            case ']':
            case '}':
                goto found;
        }
        if (js[parser->pos] < 32 || js[parser->pos] == 127)
        {
            parser->pos = start;
            return JSMN_ERROR_INVAL;
        }
    }

found:
    if (tokens == NULL)
    {
        parser->pos--;
        return 0;
    }
    jsmntok_t *token = jsmn_alloc_token(parser, tokens, num_tokens);
    if (token == NULL)
    {
        parser->pos = start;
        return JSMN_ERROR_NOMEM;
    }
    jsmn_fill_token(token, JSMN_PRIMITIVE, start, parser->pos);
    token->parent = parser->toksuper;
    parser->pos--;
    return 0;
}

static int jsmn_parse_string(jsmn_parser *parser, const char *js, size_t len, jsmntok_t *tokens, size_t num_tokens)
{
    int start = parser->pos;
    parser->pos++;

    while (parser->pos < len)
    {
        char c = js[parser->pos];

        if (c == '\"')
        {
            if (tokens == NULL)
                return 0;
            jsmntok_t *token = jsmn_alloc_token(parser, tokens, num_tokens);
            if (token == NULL)
            {
                parser->pos = start;
                return JSMN_ERROR_NOMEM;
            }
            jsmn_fill_token(token, JSMN_STRING, start + 1, parser->pos);
            token->parent = parser->toksuper;
            return 0;
        }

        if (c == '\\' && parser->pos + 1 < len)
        {
            parser->pos++;
            switch (js[parser->pos])
            {
                case '\"':
                case '/':
                case '\\':
                case 'b':
                case 'f':
                case 'r':
                case 'n':
                case 't':
                    break;
                case 'u':
                    parser->pos += 4;
                    break;
                default:
                    parser->pos = start;
                    return JSMN_ERROR_INVAL;
            }
        }
        parser->pos++;
    }
    parser->pos = start;
    return JSMN_ERROR_PART;
}

void jsmn_init(jsmn_parser *parser)
{
    parser->pos = 0;
    parser->toknext = 0;
    parser->toksuper = -1;
}

int jsmn_parse(jsmn_parser *parser, const char *js, size_t len, jsmntok_t *tokens, unsigned int num_tokens)
{
    int r;
    int count = parser->toknext;

    for (; parser->pos < len; parser->pos++)
    {
        char c = js[parser->pos];
        jsmntok_t *token;

        switch (c)
        {
            case '{':
            case '[':
                count++;
                if (tokens == NULL)
                    break;
                token = jsmn_alloc_token(parser, tokens, num_tokens);
                if (token == NULL)
                    return JSMN_ERROR_NOMEM;
                if (parser->toksuper != -1)
                {
                    tokens[parser->toksuper].size++;
                    token->parent = parser->toksuper;
                }
                token->type = (c == '{' ? JSMN_OBJECT : JSMN_ARRAY);
                token->start = parser->pos;
                parser->toksuper = parser->toknext - 1;
                break;
            case '}':
            case ']':
                if (tokens == NULL)
                    break;
                int type = (c == '}' ? JSMN_OBJECT : JSMN_ARRAY);
                int i = parser->toknext - 1;
                for (; i >= 0; i--)
                {
                    token = &tokens[i];
                    if (token->start != -1 && token->end == -1)
                    {
                        if (token->type != type)
                            return JSMN_ERROR_INVAL;
                        token->end = parser->pos + 1;
                        parser->toksuper = token->parent;
                        break;
                    }
                }
                if (i < 0)
                    return JSMN_ERROR_INVAL;
                break;
            case '\"':
                r = jsmn_parse_string(parser, js, len, tokens, num_tokens);
                if (r < 0)
                    return r;
                count++;
                if (parser->toksuper != -1 && tokens != NULL)
                    tokens[parser->toksuper].size++;
                break;
            case '\t':
            case '\r':
            case '\n':
            case ' ':
                break;
            case ':':
                parser->toksuper = parser->toknext - 1;
                break;
            case ',':
                if (tokens != NULL && parser->toksuper != -1 &&
                    tokens[parser->toksuper].type != JSMN_ARRAY &&
                    tokens[parser->toksuper].type != JSMN_OBJECT)
                {
                    parser->toksuper = tokens[parser->toksuper].parent;
                }
                break;
            default:
                r = jsmn_parse_primitive(parser, js, len, tokens, num_tokens);
                if (r < 0)
                    return r;
                count++;
                if (parser->toksuper != -1 && tokens != NULL)
                    tokens[parser->toksuper].size++;
                break;
        }
    }

    if (tokens != NULL)
    {
        for (int i = parser->toknext - 1; i >= 0; i--)
        {
            if (tokens[i].start != -1 && tokens[i].end == -1)
                return JSMN_ERROR_PART;
        }
    }

    return count;
}

#endif /* JSMN_IMPLEMENTATION */

#endif /* JSMN_H */
