#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <cstdlib>

using namespace std;

class Whisky {
private:
	string name;
	unsigned int year;
	unsigned int maxVolume;
	unsigned int curVolume;
	char* type;

public:
	Whisky(string name, unsigned int year, unsigned int maxVol, unsigned int curVol, string type)
		: year(year), maxVolume(maxVol), curVolume(curVol)
	{
		this->name = name;
		this->type = new char[type.size()];
		strcpy(this->type, type.c_str());
	}
	Whisky(const Whisky& copy) {
		name = copy.name;
		year = copy.year;
		maxVolume = copy.maxVolume;
		curVolume = copy.curVolume;
		type = new char[strlen(copy.type) + 1];
		strcpy(type, copy.type);
	}
	void printInfo() {
		cout << "Whisky name: " << name << endl;
		cout << "Aged year: " << year << endl;
		cout << "Whisky Volume: " << maxVolume << endl;
		cout << "Current Volume: " << curVolume << endl;
		cout << "Cask type: " << type << endl << endl;
	}
	bool drinkWhisky() {
		if (curVolume > 30) {
			curVolume -= 30;
			return true;
		}
		curVolume = 0;
		return false;
	}
	~Whisky() {
		delete[] type;
	}
};

class WhiskyCellar {
private:
	string cellarName;
	vector<Whisky> vec;
	unsigned int maxVolume;
	unsigned int curVolume;

public:
	WhiskyCellar(string cellarName, unsigned int maxVol)
		: maxVolume(maxVol), curVolume(0)
	{
		vec.clear();
		this->cellarName = cellarName;
	}
	WhiskyCellar(const WhiskyCellar& copy)
		: maxVolume(copy.maxVolume), curVolume(copy.curVolume)
	{
		cellarName = copy.cellarName;
		vec = copy.vec;
	}
	WhiskyCellar& operator=(const WhiskyCellar& copy) {
		cellarName = copy.cellarName;
		vec = copy.vec;
		maxVolume = copy.maxVolume;
		curVolume = copy.curVolume;
		return *this;
	}
	void addWhisky(Whisky wh) {
		curVolume += 5;
		if (curVolume > maxVolume) {
			cout << "Over." << endl;
			exit(1);
		}
		vec.push_back(wh);
	}
	void removeWhisky(unsigned int idx) {
		if (idx >= vec.size()) {
			cout << "OOB" << endl;
			exit(1);
		}
		curVolume -= 5;
		vec.erase(vec.begin() + idx);
	}
	void showWhisky(unsigned int idx) {
		vec.at(idx).printInfo();
	}
	void insertWhisky(unsigned int idx, Whisky wh) {
		vector<Whisky>::iterator iterInsertPos = vec.begin();
		iterInsertPos += idx;
		vec.insert(iterInsertPos, wh);
	}
	Whisky getIndex(unsigned int idx) {
		return vec.at(idx);
	}
	unsigned int getCellarSize() {
		return curVolume;
	}
};

class User {
public:
	string userName;
	vector<Whisky> whiskyVec;
	vector<WhiskyCellar> cellarVec;
	unsigned int money;

public:
	User(string userName)
		: money(100000)
	{
		whiskyVec.clear();
		cellarVec.clear();
		this->userName = userName;
	}
	User(const User& copy) {
		userName = copy.userName;
		whiskyVec = copy.whiskyVec;
		cellarVec = copy.cellarVec;
		money = copy.money;
	}
	User& operator=(const User& copy) {
		userName = copy.userName;
		whiskyVec = copy.whiskyVec;
		cellarVec = copy.cellarVec;
		money = copy.money;
		return *this;
	}
	void createWhisky(string name, unsigned int year, unsigned int maxVol, unsigned int curVol, string type) {
		if (curVol > 1000) {
			cout << "many" << endl;
			exit(1);
		}
		if (year > 60) {
			cout << "old" << endl;
			exit(1);
		}
		if (!type.compare("Bourbon") ||
			!type.compare("Oloroso Sherry") ||
			!type.compare("Fine Wine") ||
			!type.compare("Pedro Ximenez"))
		{
			Whisky wh(name, year, maxVol, curVol, type);
			whiskyVec.push_back(wh);
			return;
		}
		cout << "Invalid" << endl;
	}
	void deleteWhisky(unsigned int idx) {
		if (idx >= whiskyVec.size()) {
			cout << "OOB" << endl;
			exit(1);
		}
		whiskyVec.erase(whiskyVec.begin() + idx);
	}
	void drinkWhisky(unsigned int idx) {
		if (idx >= whiskyVec.size()) {
			cout << "OOB" << endl;
			exit(1);
		}
		Whisky wh = whiskyVec.at(idx);
		if (!wh.drinkWhisky()) {
			whiskyVec.erase(whiskyVec.begin() + idx);
			return;
		}
	}
	void printWhisky(unsigned int idx) {
		if (idx >= whiskyVec.size()) {
			cout << "OOB" << endl;
			exit(1);
		}
		whiskyVec.at(idx).printInfo();
	}

	void createCellar(string cellarName, unsigned int maxVol) {
		unsigned int val = maxVol * 500;
		if (money < val) {
			cout << "Dont." << endl;
			exit(1);
		}
		WhiskyCellar wh(cellarName, maxVol);
		if (cellarVec.size() > 3) {
			cout << "Many." << endl;
			exit(1);
		}
		cellarVec.push_back(wh);
	}

	void showcaseToCellar(unsigned int showcaseIdx, unsigned int cellarIdx) {
		Whisky wh = whiskyVec.at(showcaseIdx);
		cellarVec.at(cellarIdx).addWhisky(wh);
		whiskyVec.erase(whiskyVec.begin() + showcaseIdx);
	}
	void cellarToShowcase(unsigned int cellarIdx, unsigned int whiskyIdx) {
		Whisky wh = cellarVec.at(cellarIdx).getIndex(whiskyIdx);
		whiskyVec.push_back(wh);
		cellarVec.at(cellarIdx).removeWhisky(whiskyIdx);
	}
	void cellarToCellar(unsigned int cellarIdx, unsigned int whiskyIdx, unsigned int cellarIdxDest) {
		Whisky wh = cellarVec.at(cellarIdx).getIndex(whiskyIdx);
		cellarVec.at(cellarIdx).removeWhisky(whiskyIdx);
		cellarVec.at(cellarIdxDest).addWhisky(wh);
	}
	void cellarSwitch(unsigned int cellarIdx1, unsigned int whiskyIdx1, unsigned int cellarIdx2, unsigned int whiskyIdx2) {
		if ((cellarIdx1 == cellarIdx2) && (whiskyIdx1 == whiskyIdx2)) {
			cout << "DUP" << endl;
			exit(1);
		}
		Whisky wh = cellarVec.at(cellarIdx1).getIndex(whiskyIdx1);
		Whisky tmp = cellarVec.at(cellarIdx2).getIndex(whiskyIdx2);
		
		cellarVec.at(cellarIdx1).removeWhisky(whiskyIdx1);
		cellarVec.at(cellarIdx1).insertWhisky(whiskyIdx1, tmp);
		tmp = wh;
		cellarVec.at(cellarIdx2).removeWhisky(whiskyIdx2);
		cellarVec.at(cellarIdx2).insertWhisky(whiskyIdx2, tmp);
	}
	void printCellar(unsigned int idx) {
		if (idx >= cellarVec.size()) {
			cout << "OOB" << endl;
			exit(1);
		}
		for(int i = 0; i < cellarVec.at(idx).getCellarSize() / 5; ++i)
			cellarVec.at(idx).showWhisky(i);
	}
	void deleteCellar(unsigned int idx) {
		cellarVec.erase(cellarVec.begin() + idx);
	}
};

int main(void) {
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
	string buf, name, type;

	cout << "What's your name my baby? ";
	getline(cin, buf);
	User user(buf);
	unsigned int idx, year, maxVol;
	unsigned int cidx1, cidx2, sidx, didx1, didx2;

	while (1) {
		cout << "> ";
		getline(cin, buf);
		if (!buf.compare("\x11\x11")) {

			cout << "n? ";
			getline(cin, name);
			cout << "y? ";
			cin >> year;
			cout << "m? ";
			cin >> maxVol;
			cout << "t? ";
			cin >> type;

			user.createWhisky(name, year, maxVol, maxVol, type);
		}
		else if (!buf.compare("\x11\x12")) {
			cout << "n? ";
			cin >> idx;
			user.deleteWhisky(idx);
		}
		else if (!buf.compare("\x11\x13")) {
			cout << "n? ";
			cin >> idx;
			user.drinkWhisky(idx);
		}
		else if (!buf.compare("\x11\x14")) {
			cout << "n? ";
			cin >> idx;
			user.printWhisky(idx);
		}

		if (!buf.compare("\x21\x21")) {
			cout << "n? ";
			getline(cin, name);
			cout << "v? ";
			cin >> maxVol;
			user.createCellar(name, maxVol);
		}
		else if (!buf.compare("\x21\x22")) {
			cout << "n? ";
			cin >> idx;
			user.deleteCellar(idx);
		}
		else if (!buf.compare("\x21\x23")) {
			cout << "n? ";
			cin >> idx;
			user.printCellar(idx);
		}

		if (!buf.compare("\x31\x31")) { // showcase -> cellar
			cout << "si? ";
			cin >> sidx;
			cout << "ci? ";
			cin >> cidx1;
			user.showcaseToCellar(sidx, cidx1);
		}
		else if (!buf.compare("\x31\x32")) {
			cout << "ci? ";
			cin >> cidx1;
			cout << "wi? ";
			cin >> didx1;
			user.cellarToShowcase(cidx1, didx1);
		}
		else if (!buf.compare("\x31\x33")) {
			cout << "cif? ";
			cin >> cidx1;
			cout << "wif? ";
			cin >> didx1;
			cout << "cid? ";
			cin >> cidx2;
			user.cellarToCellar(cidx1, didx1, cidx2);
		}
		else if (!buf.compare("\x31\x34")) {
			cout << "cif?? ";
			cin >> cidx1;
			cout << "wif?? ";
			cin >> didx1;
			cout << "cid? ";
			cin >> cidx2;
			cout << "wid? ";
			cin >> didx2;
			user.cellarSwitch(cidx1, didx1, cidx2, didx2);
		}
	}
}
