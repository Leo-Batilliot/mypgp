NAME    =   my_pgp

SRC_DIR =   src

SRC     =   $(shell find $(SRC_DIR) -name '*.py')

all: $(NAME)

$(NAME): $(SRC)
	python3 -m zipapp $(SRC_DIR) -o $(NAME) -p "/usr/bin/env python3"
	chmod +x $(NAME)

clean:
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +

fclean: clean
	rm -f $(NAME)

re: fclean all

tests_run: $(NAME)
	MY_PGP_BIN=./$(NAME) python3 -m unittest discover -s tests -t . -v

.PHONY: all clean fclean re tests_run
