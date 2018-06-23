#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include <ayla/utypes.h>
#include <ayla/utf8.h>
#include "jsmn.h"

/**
 * Allocates a fresh unused token from the token pull.
 */
static jsmntok_t *jsmn_get_token(jsmn_parser *parser) {
	unsigned int i;
	jsmntok_t *tokens = parser->tokens;
	for (i = parser->curtoken; i<parser->num_tokens; i++) {
		if (tokens[i].start == -1 && tokens[i].end == -1) {
			parser->curtoken = i;
			tokens[i].size = 0;
			return &tokens[i];
		}
	}
	return NULL;
}

/**
 * Fills token type and boundaries.
 */
static void jsmn_fill_token(jsmntok_t *token, jsmntype_t type, 
                            int start, int end) {
	token->type = type;
	token->start = start;
	token->end = end;
}

/**
 * Initialize the parser with a max length to parse
 */
void jsmn_init_parser_len (jsmn_parser *parser, char *js, 
                      jsmntok_t *tokens, unsigned int num_tokens, int max_len) {

	jsmn_init_parser(parser, js, tokens, num_tokens);
	parser->max_len = max_len;
}

/**
 * Creates a new parser based over a given  buffer with an array of tokens 
 * available.
 */
void jsmn_init_parser(jsmn_parser *parser, char *js, 
                      jsmntok_t *tokens, unsigned int num_tokens) {
	unsigned int i;

	parser->js = js;
	parser->pos = 0;
	parser->tokens = tokens;
	parser->num_tokens = num_tokens;
	parser->curtoken = 0;
	parser->cursize = NULL;
	parser->max_len = 0;

	for (i = 0; i < parser->num_tokens; i++) {
		jsmn_fill_token(&parser->tokens[i], JSMN_PRIMITIVE, -1, -1);
	}
}

/**
 * Fills next available token with JSON primitive.
 */
static int jsmn_parse_primitive(jsmn_parser *parser) {
	const char *js;
	jsmntok_t *token;
	int start;

	start = parser->pos;

	js = parser->js;

	for (; js[parser->pos] != '\0'; parser->pos++) {
		switch (js[parser->pos]) {
			case '\t' : case '\r' : case '\n' : case ' ' :
			case ','  : case ']'  : case '}' :
				token = jsmn_get_token(parser);
				if (token == NULL)
					return JSMN_ERROR_NOMEM;
				jsmn_fill_token(token, JSMN_PRIMITIVE, start, parser->pos);
				parser->pos--;
				return JSMN_SUCCESS;
		}
		if (js[parser->pos] < 32 || js[parser->pos] >= 127) {
			parser->pos = start;
			return JSMN_ERROR_INVAL;
		}
	}
	parser->pos = start;
	return JSMN_ERROR_PART;
}

/**
 * Filsl next token with JSON string.
 */
static int jsmn_parse_string(jsmn_parser *parser) {
	char *js;
	jsmntok_t *token;
	u8 utf8_str[6];
	char unicode_str[5];
	u32 unicode;
	char *errptr;
	int start = parser->pos;
	int end = start;
	ssize_t utf8_len;

	js = parser->js;

	parser->pos++;
	end++;
	/* Skip starting quote */
	for (; js[parser->pos] != '\0'; parser->pos++) {
		char c = js[parser->pos];

		/* Quote: end of string */
		if (c == '\"') {
			token = jsmn_get_token(parser);
			if (token == NULL)
				return JSMN_ERROR_NOMEM;
			
			jsmn_fill_token(token, JSMN_STRING, start+1, end);
			return JSMN_SUCCESS;
		}

		/* Backslash: Quoted symbol expected */
		if (c == '\\') {
			parser->pos++;
			switch (js[parser->pos]) {
				/* Allowed escaped symbols */
				case '\"':
				case '/' :
				case '\\' :
					js[end++] = js[parser->pos];
					break;
				case 'b' :
					js[end++] = '\b';
					break;
				case 'f' :
					js[end++] = '\f';
					break;
				case 'r' :
					js[end++] = '\r';
					break;
				case 'n' :
					js[end++] = '\n';
					break;
				case 't' :
					js[end++] = '\t';
					break;
				/* Allows escaped symbol \uXXXX */
				case 'u':
					/* convert unicode to utf8 */
					unicode_str[0] = js[parser->pos + 1];
					unicode_str[1] = js[parser->pos + 2];
					unicode_str[2] = js[parser->pos + 3];
					unicode_str[3] = js[parser->pos + 4];
					unicode_str[4] = '\0';
					unicode = strtoul(unicode_str,
					    &errptr, 16);
					if (errptr != &unicode_str[4]) {
						return JSMN_ERROR_INVAL;
					}
					utf8_len = utf8_encode(utf8_str,
					    sizeof(utf8_str), unicode);
					if (utf8_len == -1 ||
					    utf8_len > sizeof(utf8_str)) {
						return JSMN_ERROR_INVAL;
					}
					memcpy(&js[end], utf8_str, utf8_len);
					end += utf8_len;
					parser->pos += 4;
					break;
				/* Unexpected symbol */
				default:
					parser->pos = start;
					return JSMN_ERROR_INVAL;
			}
		} else {
			js[end++] = c;
		}
	}
	parser->pos = start;
	return JSMN_ERROR_PART;
}

/**
 * Parse JSON string and fill tokens.
 */
jsmnerr_t jsmn_parse(jsmn_parser *parser) {
	int r;
	int i;
	char *js;
	jsmntype_t type;
	jsmntok_t *token;

	js = parser->js;

	if (!js) {
		return JSMN_ERROR_INVAL;
	}

	for (; js[parser->pos] != '\0'; parser->pos++) {
		char c;
		c = js[parser->pos];

		if (parser->max_len && parser->pos >= parser->max_len) {
			return JSMN_SUCCESS;
		}

		switch (c) {
			case '{': case '[':
				token = jsmn_get_token(parser);
				if (token == NULL)
					return JSMN_ERROR_NOMEM;
				if (parser->cursize != NULL)
					(*parser->cursize)++;
				token->type = (c == '{' ? JSMN_OBJECT : JSMN_ARRAY);
				token->start = parser->pos;
				parser->cursize = &token->size;
				break;
			case '}': case ']':
				type = (c == '}' ? JSMN_OBJECT : JSMN_ARRAY);
				for (i = parser->curtoken; i >= 0; i--) {
					token = &parser->tokens[i];
					if (token->start != -1 && token->end == -1) {
						if (token->type != type) {
							return JSMN_ERROR_INVAL;
						}
						parser->cursize = NULL;
						token->end = parser->pos + 1;
						break;
					}
				}
				for (; i >= 0; i--) {
					token = &parser->tokens[i];
					if (token->start != -1 && token->end == -1) {
						parser->cursize = &token->size;
						break;
					}
				}
				break;
			case '-': case '0': case '1' : case '2': case '3' : case '4':
			case '5': case '6': case '7' : case '8': case '9':
			case 't': case 'f': case 'n' :
				r = jsmn_parse_primitive(parser);
				if (r < 0) return r;
				if (parser->cursize != NULL)
					(*parser->cursize)++;
				break;
			case '\"':
				r = jsmn_parse_string(parser);
				if (r < 0) return r;
				if (parser->cursize != NULL)
					(*parser->cursize)++;
				break;
			case '\t' : case '\r' : case '\n' : case ':' : case ',': case ' ': 
				break;
			default:
				return JSMN_ERROR_INVAL;
		}
	}
	return JSMN_SUCCESS;
}

