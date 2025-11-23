all:
	cc -fsanitize=address,undefined -g -O0 -o ssfx ssfx.c main.c -Wall -Wextra -Wpedantic
format:
	clang-format -i *.c include/*.h
test: all
	rm -rf ./test
	rm x|| true
	printf "#!/bin/bash\necho Hello, SSFX!" > x
	chmod +x x
	tar -cf x.tar ./x
	mv x.tar ./x
	./ssfx /usr/bin/tar ./ssfx_master
	./ssfx_master ./x ./out x
	./out
	./ssfx_master
	diff ssfx origional_exe_dumped||echo "Origional exe dump differs!"
	diff /usr/bin/tar ssfx_tmp_tar_exe||echo "Tar exe dump differs!"