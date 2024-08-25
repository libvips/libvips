/* compile with
 *
 * 		gcc -g -Wall token.c `pkg-config vips --cflags --libs`
 *
 * 	run with eg.:
 *
 * 		$ ./a.out '"wdfw"df,wdw,dw' 3 wdfw df,wdw,dw
 *
 */

#include <vips/vips.h>

char *token_names[] = {
	"",
	"left",
	"right",
	"string",
	"equals",
	"comma",
};

int
main(int argc, char **argv)
{
	if (VIPS_INIT(argv[0]))
		vips_error_exit(NULL);

	if (argc != 5)
		vips_error_exit("usage: %s string-to-parse token token-string residual",
			argv[0]);

	const char *p = argv[1];
	printf("argv[1]:\n");
	for (int i = 0; i < strlen(p); i++)
		printf("\t\t%2d) %02x %c\n", i, p[i], p[i]);

	VipsToken token;
	char buf[256];
	p = vips__token_get(p, &token, buf, 256);

	printf("vips__token_get:\n");
	printf("\ttoken = %d (%s)\n", token, token_names[token]);
	if (token == VIPS_TOKEN_STRING) {
		printf("\tbuf = <%s>\n", buf);
		for (int i = 0; i < strlen(buf); i++)
			printf("\t\t%2d) 0x%02x %c\n", i, buf[i], buf[i]);
	}
	printf("\tresidual = <%s>\n", p);

	if (token != atoi(argv[2]))
		vips_error_exit("token mismatch");
	if (token == VIPS_TOKEN_STRING &&
		!g_str_equal(buf, argv[3]))
		vips_error_exit("parsed string mismatch");
	if (!g_str_equal(p, argv[4]))
		vips_error_exit("residual mismatch");

	return 0;
}
