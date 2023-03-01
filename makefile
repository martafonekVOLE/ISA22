default:
	g++ main.cpp -o flow -lpcap
checkFiles:
	test -f main.cpp && echo "Files OK" || echo "File main.cpp missing"
clear: 
	rm -f flow
clearAll: rm -f *
