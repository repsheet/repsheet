ifndef RM_INCLUDE_DIR
	RM_INCLUDE_DIR=./
endif

ifndef RMUTIL_LIBDIR
	RMUTIL_LIBDIR=rmutil
endif

ifndef SRC_DIR
	SRC_DIR=src
endif

all: repsheet.so

repsheet.so:
	$(MAKE) -C ./$(SRC_DIR)
	cp ./$(SRC_DIR)/repsheet.so .

run: repsheet.so
	redis-server --loadmodule src/repsheet.so

.PHONY: docker
docker:
	docker build -t repsheet-redis .

.PHONY: docker-run
docker-run: docker
	docker run -p 6379:6379 repsheet-redis

virtualenv:
	virtualenv -p python3 venv
	venv/bin/pip install -r requirements.txt

test: FORCE
	venv/bin/pytest -v --disable-warnings test

clean: FORCE
	rm -rf *.xo *.so *.o
	rm -rf ./$(SRC_DIR)/*.xo ./$(SRC_DIR)/*.so ./$(SRC_DIR)/*.o
	rm -rf ./$(RMUTIL_LIBDIR)/*.so ./$(RMUTIL_LIBDIR)/*.o ./$(RMUTIL_LIBDIR)/*.a

FORCE:
