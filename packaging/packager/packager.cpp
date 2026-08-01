// Legacy standalone manifest generator.
//
// The canonical release path is build_dist.ps1, which generates and validates
// a manifest in an isolated staging directory. This helper remains for project
// compatibility and writes its output atomically.

#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

#include <pluginsdk/PluginDefs.h>
#include <src/version.h>

using namespace std;

namespace {

string escapeXml(string value) {
	size_t i = 0;
	while((i = value.find_first_of("<>&", i)) != string::npos) {
		switch(value[i]) {
		case '<': value.replace(i, 1, "&lt;"); i += 4; break;
		case '>': value.replace(i, 1, "&gt;"); i += 4; break;
		case '&': value.replace(i, 1, "&amp;"); i += 5; break;
		default: ++i; break;
		}
	}
	return value;
}

string makeManifest() {
	ostringstream out;
	out << "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n"
		"<dcext>\n"
		"\t<UUID>" << escapeXml(PLUGIN_GUID) << "</UUID>\n"
		"\t<Name>" << escapeXml(PLUGIN_NAME) << "</Name>\n"
		"\t<Version>" << PLUGIN_VERSION_STR << "</Version>\n"
		"\t<ApiVersion>" << DCAPI_CORE_VER << "</ApiVersion>\n"
		"\t<Author>" << escapeXml(PLUGIN_AUTHOR) << "</Author>\n"
		"\t<Description>" << escapeXml(PLUGIN_DESC) << "</Description>\n"
		"\t<Website>" << escapeXml(PLUGIN_WEB) << "</Website>\n"
		"\t<Plugin Platform=\"pe-x64\">ProtocolAnalyzer.dll</Plugin>\n"
		"\t<Files>\n"
		"\t\t<File Platform=\"pe-x64\">ProtocolAnalyzer.dbg</File>\n"
		"\t\t<File>ProtocolAnalyzer.ico</File>\n"
		"\t\t<File>LICENSE.txt</File>\n"
		"\t\t<File>GPL-2.0.txt</File>\n"
		"\t\t<File>LibDWT-License.txt</File>\n"
		"\t\t<File>THIRD-PARTY.txt</File>\n"
		"\t\t<File>BUILD-PROVENANCE.txt</File>\n"
		"\t\t<File>SHA256SUMS</File>\n"
		"\t</Files>\n"
		"</dcext>\n";
	return out.str();
}

bool replaceFile(const string& temporaryPath, const string& destinationPath) {
#ifdef _WIN32
	return MoveFileExA(
		temporaryPath.c_str(),
		destinationPath.c_str(),
		MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
#else
	if(rename(temporaryPath.c_str(), destinationPath.c_str()) == 0) {
		return true;
	}
	remove(destinationPath.c_str());
	return rename(temporaryPath.c_str(), destinationPath.c_str()) == 0;
#endif
}

} // namespace

int main(int argc, char* argv[]) {
	if(argc != 2) {
		cerr << "packager: expected exactly one output path" << endl;
		return 1;
	}

	const string destinationPath = argv[1];
	const string temporaryPath = destinationPath + ".tmp";
	const string manifest = makeManifest();

	{
		ofstream file(temporaryPath, ios::binary | ios::trunc);
		if(!file.is_open()) {
			cerr << "packager: cannot open temporary output " << temporaryPath << endl;
			return 2;
		}
		file.write(manifest.data(), static_cast<streamsize>(manifest.size()));
		file.flush();
		if(!file.good()) {
			cerr << "packager: failed while writing " << temporaryPath << endl;
			file.close();
			remove(temporaryPath.c_str());
			return 3;
		}
	}

	if(!replaceFile(temporaryPath, destinationPath)) {
		cerr << "packager: cannot replace " << destinationPath << endl;
		remove(temporaryPath.c_str());
		return 4;
	}

	return 0;
}
