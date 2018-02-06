SuperFTP - Pwn 600pt (13 Teams Solved)
-------------
### Description
SuperFTP is simple x86-menu challenge with ASLR+NX+SSP+PIE+Full RELRO.

Phase 1. Reversing

ASLR + NX + SSP + PIE + RELRO가 걸려있는 32bit 바이너리이다.

main 함수에선 gInit함수를 호출해 전역변수 g에 malloc()을 할당해 초기화한 후 flag 1를 1로 설정한다.
이후 while() 문 안에서 메뉴를 입력받고 해당하는 메뉴의 동작을 한다.
메뉴에는 다음 종류가 있다.

	* Join
	* Print your info
	* Login
	* Withdrawal
	* Download Files
	* Exit


Join:
스택에 있는 info 포인터를 join()의 인자로 전달한다.
Name, age, ID, PW를 getline()으로 입력받고 account 객체를 생성, 포인터에 저장한다.
account 객체는 (id, pw, name) 3개의 string 객체 72byte와 age 4byte, 총 76byte로 구성돼있다.

Print your info:
flag3을 검사한다. ( info 포인터가 아닌 flag3을 검사 )
valid라면, name, id, age를 출력한다. 

Login:
id와 pw를 입력받는다. // cin
id가 "admin"이고 pw가 "P3ssw0rd"라면 flag2, flag3을 1로 설정하고 리턴한다.
id가 info->ID와 일치하고 pw가 info->PW와 일치하면 flag2를 0, flag3을 1로 설정하고 리턴한다.
그 외의 경우에는 flag2, flag3을 0으로 설정하고 리턴한다.

Withdrawal:
flag3을 검사한다.
info 안에 있는 3개의 string을 free하고 info도 free, info를 nullify한다.

Download Files:
flag3이 유효할 경우 downloadFile()을 호출한다.
downloadFile() 안에선 downloadFile_()를 호출하고 "Essential Maintenance In Progress" 문자열을 출력한다.
downloadFile_()에선 가장 먼저 다운로드할 URL을 입력받는다. (URL은 string 객체이다.)
입력받은 URL의 begin과 end를 인자로 reverse() 함수를 호출한다.
이후 g에 reversed string을 복사하고 parse() 함수를 호출한다.
v12에 g에 저장된 string을 basic_string()을 통해 복사하고, begin_과 end_를 설정한다.
reverse(begin_, end_)함수를 호출해 다시 문자열을 뒤집는다.
최종적으로 "result: " + v12를 출력한다.
g를 nullify한 후 함수를 리턴한다.

// IDA에서 call-by-reference는 주솟값을 전달했을 때만. 포인터로 전달한다 하더라도 call-by-value면 그것은 value인 것.

reverse:
내부적으로 begin과 end 포인터를 call-by-value 방식으로 전달해준다.
while문 내부에서 begin < end를 만족할 때 begin과 end의 1byte를 swap해주고 begin은 1 증가, end는 1 감소한다.

parse:
처음에 buf 포인터가 g_URL을 가리킨다. (g_URL은 우리가 넣어준 입력의 reverse)
(/aa/../bb => bb/../aa/)
(/aa/../bb/../cc => cc/../bb/../aa/)
"/../"를 만날 때까지 검색하고, "/../"를 만난다면 "/"의 첫 index가 idx에 저장된다.
idx+4부터 다음 slash를 만날 때까지 검색을 계속한다. (aa/)
이후 g_URL[slash-i] = g_URL[idx-i]로 slash 이전에 /../ 전까지 있었던 문자열을 복사한다. 
g_URL += slash-idx;
g_URL이 cc/../bb/../aa/라면 g_URL은 이제 cc/../aa/를 가리킨다.
이 함수를 재귀적으로 호출해 루틴을 완료한다.

Menu 7:
flag 2가 설정되어 있을 때 flag 1을 설정한다.

Menu 8:
flag 1이 설정되어 있을 때 진입할 수 있다.
Menu 8에서는 4가지 메뉴를 제공한다.
8-1:
downloadFileStack() 함수를 호출한다.
downloadFileStack() 함수에선 g를 스택 버퍼로 설정한 후 downloadFile()과 동일한 일을 한다.
8-2:
flag3을 출력한다.
8-3:
flag2를 출력한다.
8-4:
flag1을 출력한다.

Phase 2. Vulnerability analysis
Print your info에서 info 포인터가 아닌 flag 검사를 통해 유효성을 검사하므로 flag를 변조한다면 취약하다.
Login에서 id와 pw가 string 객체가 아닌 스택 배열이기 때문에 버퍼 오버플로우가 발생한다.
hidden menu의 URL을 입력받는 부분에서 string 객체가 아닌 스택 배열에 입력받기 때문에 버퍼 오버플로우가 발생한다.
parse 함수 내부에서 /../ 이후 다음 slash를 찾을 때 Boundary check가 존재하지 않는다.

Phase 3. Exploit
(방법론 1)
따라서 우리는 0x2f 위치부터 그 아래로 Buffer write를 할 수 있다.
만약 스택에 0x2f 값을 넣어줄 수 있다면, 역순으로 write할 때 stack canary가 return address보다 밑에 있으므로 Canary를 건드리지 않고 eip를 변조할 수 있다.
프로그램 스택으로 보면 main()함수에서 menu 8()을 호출하고 menu 8()에서 downloadFileStack() 함수를 호출한다.
main()함수의 스택에 있는 login cnt를 0x2f로 변경한다면, login cnt 아래로 /../../ 이후에 작성된 페이로드가 역으로 입력된다.
따라서 맨 처음에 /../../을 통해 library 주소를 구하고, 이후 위 방법으로 main 함수 아래에 있는 menu 8 함수의 리턴 어드레스를 system()으로 덮고 인자로 binsh 주소를 전달하면 된다.

