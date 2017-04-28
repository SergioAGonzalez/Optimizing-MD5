all:
	gcc main_base.c -std=c99 -mavx2 -O0 -o pwck0_O0
	gcc main_base.c -std=c99 -mavx2 -O1 -fomit-frame-pointer -o pwck0_O1
	gcc main_base.c -std=c99 -mavx2 -O2 -fomit-frame-pointer -o pwck0_O2
	gcc main_base.c -std=c99 -mavx2 -O3 -fomit-frame-pointer -o pwck0_O3
	gcc main_base_clean.c -std=c99 -mavx2 -O0 -o pwck1_O0
	gcc main_base_clean.c -std=c99 -mavx2 -O1 -fomit-frame-pointer -o pwck1_O1
	gcc main_base_clean.c -std=c99 -mavx2 -O2 -fomit-frame-pointer -o pwck1_O2
	gcc main_base_clean.c -std=c99 -mavx2 -O3 -fomit-frame-pointer -o pwck1_O3
	gcc main_threaded.c -std=c99 -lpthread -mavx2 -O0 -o pwck2_O0
	gcc main_threaded.c -std=c99 -lpthread -mavx2 -O1 -fomit-frame-pointer -o pwck2_O1
	gcc main_threaded.c -std=c99 -lpthread -mavx2 -O2 -fomit-frame-pointer -o pwck2_O2
	gcc main_threaded.c -std=c99 -lpthread -mavx2 -O3 -fomit-frame-pointer -o pwck2_O3
	gcc main_threaded_clean.c -std=c99 -lpthread -mavx2 -O0 -o pwck1_O0
	gcc main_threaded_clean.c -std=c99 -lpthread -mavx2 -O1 -fomit-frame-pointer -o pwck3_O1
	gcc main_threaded_clean.c -std=c99 -lpthread -mavx2 -O2 -fomit-frame-pointer -o pwck3_O2
	gcc main_threaded_clean.c -std=c99 -lpthread -mavx2 -O3 -fomit-frame-pointer -o pwck3_O3

