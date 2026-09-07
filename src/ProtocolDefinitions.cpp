/*
* Copyright (C) 2022-2026 iceman50
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*/

#include "ProtocolDefinitions.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <string_view>
#include <utility>
#include <vector>

namespace protocol_analyzer {
namespace {

using std::string;
using std::string_view;

constexpr std::size_t MAX_XML_BYTES = 1024U * 1024U;
constexpr std::size_t MAX_XML_ELEMENTS = 8192;
constexpr std::size_t MAX_XML_DEPTH = 8;
constexpr std::size_t MAX_XML_ATTRIBUTES = 16;
constexpr std::size_t MAX_ATTRIBUTE_BYTES = 4096;
constexpr std::size_t MAX_COMMANDS = 1024;
constexpr std::size_t MAX_FEATURES = 1024;
constexpr std::size_t MAX_FIELDS = 4096;

struct XmlNode {
	string name;
	std::map<string, string> attributes;
	std::vector<XmlNode> children;
};

class XmlParser {
public:
	explicit XmlParser(string_view source) : source_(source) { }

	bool parse(XmlNode& root, string& error) {
		if(source_.size() > MAX_XML_BYTES) {
			return fail(error, "XML catalog exceeds the 1 MiB safety limit");
		}
		if(source_.size() >= 3 &&
			static_cast<unsigned char>(source_[0]) == 0xefU &&
			static_cast<unsigned char>(source_[1]) == 0xbbU &&
			static_cast<unsigned char>(source_[2]) == 0xbfU)
		{
			position_ = 3;
		}
		skipWhitespace();
		if(startsWith("<?xml")) {
			const auto end = source_.find("?>", position_ + 5);
			if(end == string_view::npos) {
				return fail(error, "unterminated XML declaration");
			}
			position_ = end + 2;
		}
		if(!skipMisc(error)) {
			return false;
		}
		if(position_ >= source_.size()) {
			return fail(error, "XML catalog has no root element");
		}
		if(!parseNode(root, 0, error)) {
			return false;
		}
		if(!skipMisc(error)) {
			return false;
		}
		if(position_ != source_.size()) {
			return fail(error, "unexpected content after the root element");
		}
		return true;
	}

private:
	bool fail(string& error, const string& message) const {
		error = message + " at byte " + std::to_string(position_);
		return false;
	}

	bool startsWith(string_view value) const {
		return source_.substr(position_, value.size()) == value;
	}

	void skipWhitespace() {
		while(position_ < source_.size()) {
			const char ch = source_[position_];
			if(ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') {
				break;
			}
			++position_;
		}
	}

	bool skipComment(string& error) {
		const auto end = source_.find("-->", position_ + 4);
		if(end == string_view::npos) {
			return fail(error, "unterminated XML comment");
		}
		position_ = end + 3;
		return true;
	}

	bool skipMisc(string& error) {
		for(;;) {
			skipWhitespace();
			if(!startsWith("<!--")) {
				return true;
			}
			if(!skipComment(error)) {
				return false;
			}
		}
	}

	static bool isNameStart(char ch) {
		return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
			ch == '_' || ch == ':';
	}

	static bool isNameChar(char ch) {
		return isNameStart(ch) || (ch >= '0' && ch <= '9') || ch == '-' || ch == '.';
	}

	bool parseName(string& name, string& error) {
		if(position_ >= source_.size() || !isNameStart(source_[position_])) {
			return fail(error, "expected an XML name");
		}
		const auto start = position_++;
		while(position_ < source_.size() && isNameChar(source_[position_])) {
			++position_;
		}
		name.assign(source_.substr(start, position_ - start));
		return true;
	}

	static void appendCodePoint(string& output, std::uint32_t value) {
		if(value <= 0x7fU) {
			output.push_back(static_cast<char>(value));
		} else if(value <= 0x7ffU) {
			output.push_back(static_cast<char>(0xc0U | (value >> 6U)));
			output.push_back(static_cast<char>(0x80U | (value & 0x3fU)));
		} else if(value <= 0xffffU) {
			output.push_back(static_cast<char>(0xe0U | (value >> 12U)));
			output.push_back(static_cast<char>(0x80U | ((value >> 6U) & 0x3fU)));
			output.push_back(static_cast<char>(0x80U | (value & 0x3fU)));
		} else {
			output.push_back(static_cast<char>(0xf0U | (value >> 18U)));
			output.push_back(static_cast<char>(0x80U | ((value >> 12U) & 0x3fU)));
			output.push_back(static_cast<char>(0x80U | ((value >> 6U) & 0x3fU)));
			output.push_back(static_cast<char>(0x80U | (value & 0x3fU)));
		}
	}

	bool decodeEntity(string& output, string& error) {
		const auto semicolon = source_.find(';', position_ + 1);
		if(semicolon == string_view::npos || semicolon - position_ > 12) {
			return fail(error, "invalid XML entity");
		}
		const auto entity = source_.substr(position_ + 1, semicolon - position_ - 1);
		if(entity == "amp") output.push_back('&');
		else if(entity == "lt") output.push_back('<');
		else if(entity == "gt") output.push_back('>');
		else if(entity == "quot") output.push_back('"');
		else if(entity == "apos") output.push_back('\'');
		else if(!entity.empty() && entity.front() == '#') {
			std::uint32_t value = 0;
			std::size_t offset = 1;
			unsigned base = 10;
			if(offset < entity.size() && (entity[offset] == 'x' || entity[offset] == 'X')) {
				base = 16;
				++offset;
			}
			if(offset == entity.size()) {
				return fail(error, "empty numeric XML entity");
			}
			for(; offset < entity.size(); ++offset) {
				const char ch = entity[offset];
				unsigned digit = 0;
				if(ch >= '0' && ch <= '9') digit = static_cast<unsigned>(ch - '0');
				else if(base == 16 && ch >= 'a' && ch <= 'f') digit = 10U + static_cast<unsigned>(ch - 'a');
				else if(base == 16 && ch >= 'A' && ch <= 'F') digit = 10U + static_cast<unsigned>(ch - 'A');
				else return fail(error, "invalid numeric XML entity");
				if(value > (0x10ffffU - digit) / base) {
					return fail(error, "numeric XML entity is out of range");
				}
				value = value * base + digit;
			}
			if(value == 0 || value > 0x10ffffU ||
				(value >= 0xd800U && value <= 0xdfffU) ||
				(value < 0x20U && value != 0x09U && value != 0x0aU && value != 0x0dU))
			{
				return fail(error, "numeric XML entity is not a valid XML character");
			}
			appendCodePoint(output, value);
		} else {
			return fail(error, "unsupported XML entity");
		}
		position_ = semicolon + 1;
		return true;
	}

	bool parseAttributeValue(string& value, string& error) {
		if(position_ >= source_.size() ||
			(source_[position_] != '"' && source_[position_] != '\''))
		{
			return fail(error, "expected a quoted XML attribute");
		}
		const char quote = source_[position_++];
		while(position_ < source_.size() && source_[position_] != quote) {
			const auto ch = static_cast<unsigned char>(source_[position_]);
			if(ch == '&') {
				if(!decodeEntity(value, error)) return false;
			} else {
				if(ch == '<' || ch == 0 || (ch < 0x20U && ch != 0x09U && ch != 0x0aU && ch != 0x0dU)) {
					return fail(error, "invalid character in XML attribute");
				}
				value.push_back(source_[position_++]);
			}
			if(value.size() > MAX_ATTRIBUTE_BYTES) {
				return fail(error, "XML attribute exceeds the safety limit");
			}
		}
		if(position_ >= source_.size()) {
			return fail(error, "unterminated XML attribute");
		}
		++position_;
		return true;
	}

	bool parseNode(XmlNode& node, std::size_t depth, string& error) {
		if(depth >= MAX_XML_DEPTH) return fail(error, "XML nesting is too deep");
		if(++elementCount_ > MAX_XML_ELEMENTS) return fail(error, "XML has too many elements");
		if(position_ >= source_.size() || source_[position_] != '<') {
			return fail(error, "expected an XML element");
		}
		++position_;
		if(position_ < source_.size() && (source_[position_] == '!' || source_[position_] == '?')) {
			return fail(error, "XML declarations, CDATA, and processing instructions are not allowed here");
		}
		if(!parseName(node.name, error)) return false;

		for(;;) {
			skipWhitespace();
			if(startsWith("/>")) {
				position_ += 2;
				return true;
			}
			if(position_ < source_.size() && source_[position_] == '>') {
				++position_;
				break;
			}
			if(node.attributes.size() >= MAX_XML_ATTRIBUTES) {
				return fail(error, "XML element has too many attributes");
			}
			string key;
			if(!parseName(key, error)) return false;
			skipWhitespace();
			if(position_ >= source_.size() || source_[position_] != '=') {
				return fail(error, "expected '=' after XML attribute name");
			}
			++position_;
			skipWhitespace();
			string value;
			if(!parseAttributeValue(value, error)) return false;
			if(!node.attributes.emplace(std::move(key), std::move(value)).second) {
				return fail(error, "duplicate XML attribute");
			}
		}

		for(;;) {
			if(position_ >= source_.size()) return fail(error, "unterminated XML element");
			if(startsWith("</")) {
				position_ += 2;
				string closing;
				if(!parseName(closing, error)) return false;
				skipWhitespace();
				if(position_ >= source_.size() || source_[position_] != '>') {
					return fail(error, "malformed XML closing tag");
				}
				++position_;
				if(closing != node.name) return fail(error, "mismatched XML closing tag");
				return true;
			}
			if(startsWith("<!--")) {
				if(!skipComment(error)) return false;
				continue;
			}
			if(source_[position_] == '<') {
				node.children.emplace_back();
				if(!parseNode(node.children.back(), depth + 1, error)) return false;
				continue;
			}
			const auto textStart = position_;
			while(position_ < source_.size() && source_[position_] != '<') ++position_;
			if(std::any_of(source_.begin() + static_cast<std::ptrdiff_t>(textStart),
				source_.begin() + static_cast<std::ptrdiff_t>(position_), [](char ch) {
					return ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n';
				}))
			{
				return fail(error, "definition XML may only use attribute text");
			}
		}
	}

	string_view source_;
	std::size_t position_ = 0;
	std::size_t elementCount_ = 0;
};

struct Catalog {
	string source;
	string language;
	std::map<string, ProtocolCommandDefinition> commands;
	std::map<string, ProtocolFeatureDefinition> features;
	std::map<string, ProtocolFieldDefinition> fields;
};

std::shared_ptr<const Catalog> activeCatalog;

string key(string_view family, string_view value) {
	return string(family) + '\x1f' + string(value);
}

string fieldKey(string_view family, string_view command, string_view code) {
	return string(family) + '\x1f' + string(command) + '\x1f' + string(code);
}

string asciiLower(string value) {
	std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
		if(ch >= 'A' && ch <= 'Z') return static_cast<char>(ch - 'A' + 'a');
		return static_cast<char>(ch);
	});
	std::replace(value.begin(), value.end(), '_', '-');
	return value;
}

string baseLanguage(const string& language) {
	const auto delimiter = language.find('-');
	return delimiter == string::npos ? language : language.substr(0, delimiter);
}

const string* attribute(const XmlNode& node, const char* name) {
	const auto found = node.attributes.find(name);
	return found == node.attributes.end() ? nullptr : &found->second;
}

bool requireAttribute(const XmlNode& node, const char* name, string& value, string& error) {
	const auto found = attribute(node, name);
	if(!found || found->empty()) {
		error = "<" + node.name + "> requires a non-empty '" + name + "' attribute";
		return false;
	}
	value = *found;
	return true;
}

bool isValidUtf8(const string& value) {
	for(std::size_t index = 0; index < value.size();) {
		const auto first = static_cast<unsigned char>(value[index]);
		if(first < 0x80U) {
			++index;
			continue;
		}
		std::size_t length = 0;
		if(first >= 0xc2U && first <= 0xdfU) length = 2;
		else if(first >= 0xe0U && first <= 0xefU) length = 3;
		else if(first >= 0xf0U && first <= 0xf4U) length = 4;
		else return false;
		if(index + length > value.size()) return false;
		for(std::size_t offset = 1; offset < length; ++offset) {
			if((static_cast<unsigned char>(value[index + offset]) & 0xc0U) != 0x80U) {
				return false;
			}
		}
		const auto second = static_cast<unsigned char>(value[index + 1]);
		if((first == 0xe0U && second < 0xa0U) ||
			(first == 0xedU && second > 0x9fU) ||
			(first == 0xf0U && second < 0x90U) ||
			(first == 0xf4U && second > 0x8fU))
		{
			return false;
		}
		index += length;
	}
	return true;
}

bool validDefinitionText(const string& value, std::size_t maximum) {
	return !value.empty() && value.size() <= maximum &&
		std::none_of(value.begin(), value.end(), [](unsigned char ch) {
			return ch < 0x20U || ch == 0x7fU;
		}) && isValidUtf8(value);
}

bool isAdcCode(const string& value, std::size_t size) {
	if(value.size() != size || value.front() < 'A' || value.front() > 'Z') return false;
	return std::all_of(value.begin() + 1, value.end(), [](char ch) {
		return (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9');
	});
}

bool isNmdcCommand(const string& value) {
	if(value == "Chat" || value == "KEEPALIVE") return true;
	if(value.size() < 2 || value.size() > 64 || value.front() != '$' ||
		!((value[1] >= 'A' && value[1] <= 'Z') ||
			(value[1] >= 'a' && value[1] <= 'z'))) return false;
	return std::all_of(value.begin() + 2, value.end(), [](unsigned char ch) {
		return ch >= 0x21U && ch <= 0x7eU && ch != '$' && ch != '<' && ch != '>' && ch != '|';
	});
}

bool validSimpleCode(const string& value, std::size_t maximum = 64) {
	return !value.empty() && value.size() <= maximum &&
		std::all_of(value.begin(), value.end(), [](unsigned char ch) {
			return ch >= 0x21U && ch <= 0x7eU && ch != '<' && ch != '>' && ch != '|';
		});
}

int languageScore(const string& candidate, const string& preferred,
	const string& defaultLanguage)
{
	const auto normalized = asciiLower(candidate);
	if(normalized == preferred) return 4;
	if(normalized == baseLanguage(preferred)) return 3;
	if(normalized == defaultLanguage) return 2;
	if(normalized == baseLanguage(defaultLanguage)) return 1;
	return 0;
}

void applyLocalization(const XmlNode& node, const string& preferred,
	const string& defaultLanguage, string& name, string* category,
	string& description)
{
	const XmlNode* selected = nullptr;
	int selectedScore = 0;
	for(const auto& child : node.children) {
		if(child.name != "translation") continue;
		const auto language = attribute(child, "language");
		if(!language) continue;
		const auto score = languageScore(*language, preferred, defaultLanguage);
		if(score > selectedScore) {
			selected = &child;
			selectedScore = score;
		}
	}
	if(!selected) return;
	if(const auto value = attribute(*selected, "name")) name = *value;
	if(category) {
		if(const auto value = attribute(*selected, "category")) *category = *value;
	}
	if(const auto value = attribute(*selected, "description")) description = *value;
}

bool validateTranslation(const XmlNode& node, string& error) {
	if(node.name != "translation") {
		error = "unexpected <" + node.name + "> child element";
		return false;
	}
	string language;
	if(!requireAttribute(node, "language", language, error)) return false;
	if(!validSimpleCode(language, 35)) {
		error = "translation language is invalid";
		return false;
	}
	if(!node.children.empty()) {
		error = "<translation> cannot contain child elements";
		return false;
	}
	return true;
}

bool buildText(const XmlNode& node, const string& preferred,
	const string& defaultLanguage, string& name, string* category,
	string& description, string& error)
{
	if(!requireAttribute(node, "name", name, error)) return false;
	if(category && !requireAttribute(node, "category", *category, error)) return false;
	if(const auto value = attribute(node, "description")) description = *value;
	applyLocalization(node, preferred, defaultLanguage, name, category, description);
	if(!validDefinitionText(name, 256) ||
		(category && !validDefinitionText(*category, 128)) ||
		(!description.empty() && !validDefinitionText(description, 1024)))
	{
		error = "definition text is empty, unsafe, or too long in <" + node.name + ">";
		return false;
	}
	return true;
}

bool addField(Catalog& catalog, const XmlNode& node, const string& family,
	const string& command, const string& preferred, const string& defaultLanguage,
	string& error)
{
	string code;
	if(!requireAttribute(node, "code", code, error)) return false;
	if(!validSimpleCode(code)) {
		error = "field code is invalid: " + code;
		return false;
	}
	ProtocolFieldDefinition definition;
	if(!buildText(node, preferred, defaultLanguage, definition.name, nullptr,
		definition.description, error)) return false;
	for(const auto& child : node.children) {
		if(!validateTranslation(child, error)) return false;
	}
	if(catalog.fields.size() >= MAX_FIELDS) {
		error = "XML catalog has too many fields";
		return false;
	}
	if(!catalog.fields.emplace(fieldKey(family, command, code), std::move(definition)).second) {
		error = "duplicate field definition for " + family + " " + command + " " + code;
		return false;
	}
	return true;
}

bool buildCatalog(const XmlNode& root, const string& preferredLanguage,
	const string& source, Catalog& catalog, string& error)
{
	if(root.name != "protocol-definitions") {
		error = "root element must be <protocol-definitions>";
		return false;
	}
	const auto version = attribute(root, "version");
	if(!version || *version != "1") {
		error = "protocol definition XML requires version=\"1\"";
		return false;
	}
	string defaultLanguage = "en";
	if(const auto value = attribute(root, "default-language")) defaultLanguage = asciiLower(*value);
	if(!validSimpleCode(defaultLanguage, 35)) {
		error = "default-language is invalid";
		return false;
	}
	const auto preferred = asciiLower(preferredLanguage.empty() ? defaultLanguage : preferredLanguage);
	catalog.source = source;
	catalog.language = preferred;
	std::map<string, bool> protocols;

	for(const auto& protocol : root.children) {
		if(protocol.name != "protocol") {
			error = "unexpected <" + protocol.name + "> under <protocol-definitions>";
			return false;
		}
		string family;
		if(!requireAttribute(protocol, "id", family, error)) return false;
		if(family != "ADC" && family != "NMDC") {
			error = "unsupported protocol id: " + family;
			return false;
		}
		if(!protocols.emplace(family, true).second) {
			error = "duplicate protocol section: " + family;
			return false;
		}

		for(const auto& node : protocol.children) {
			if(node.name == "command") {
				string code;
				if(!requireAttribute(node, "code", code, error)) return false;
				if((family == "ADC" && code != "KEEPALIVE" && !isAdcCode(code, 3)) ||
					(family == "NMDC" && !isNmdcCommand(code)))
				{
					error = "invalid " + family + " command code: " + code;
					return false;
				}
				ProtocolCommandDefinition definition;
				if(!buildText(node, preferred, defaultLanguage, definition.name,
					&definition.category, definition.description, error)) return false;
				if(const auto routing = attribute(node, "routing")) {
					definition.routing = *routing;
					if(family != "ADC" || definition.routing.empty() ||
						!std::all_of(definition.routing.begin(), definition.routing.end(), [](char ch) {
							return string_view("BCDEFHIU").find(ch) != string_view::npos;
						}))
					{
						error = "routing must contain only ADC routing letters";
						return false;
					}
				}
				if(catalog.commands.size() >= MAX_COMMANDS ||
					!catalog.commands.emplace(key(family, code), std::move(definition)).second)
				{
					error = "duplicate or excessive command definition: " + family + " " + code;
					return false;
				}
				for(const auto& child : node.children) {
					if(child.name == "translation") {
						if(!validateTranslation(child, error)) return false;
					} else if(child.name == "field") {
						if(!addField(catalog, child, family, code, preferred,
							defaultLanguage, error)) return false;
					} else {
						error = "unexpected <" + child.name + "> under <command>";
						return false;
					}
				}
			} else if(node.name == "feature") {
				string code;
				if(!requireAttribute(node, "code", code, error)) return false;
				if((family == "ADC" && !isAdcCode(code, 4)) ||
					(family == "NMDC" && !validSimpleCode(code)))
				{
					error = "invalid " + family + " feature code: " + code;
					return false;
				}
				ProtocolFeatureDefinition definition;
				if(!buildText(node, preferred, defaultLanguage, definition.name,
					nullptr, definition.description, error)) return false;
				for(const auto& child : node.children) {
					if(!validateTranslation(child, error)) return false;
				}
				if(catalog.features.size() >= MAX_FEATURES ||
					!catalog.features.emplace(key(family, code), std::move(definition)).second)
				{
					error = "duplicate or excessive feature definition: " + family + " " + code;
					return false;
				}
			} else if(node.name == "field") {
				if(!addField(catalog, node, family, "*", preferred,
					defaultLanguage, error)) return false;
			} else {
				error = "unexpected <" + node.name + "> under <protocol>";
				return false;
			}
		}
	}
	if(catalog.commands.empty()) {
		error = "XML catalog contains no command definitions";
		return false;
	}
	return true;
}

} // namespace

ProtocolDefinitionLoadResult loadProtocolDefinitionsXml(const string& xml,
	const string& preferredLanguage, const string& source)
{
	ProtocolDefinitionLoadResult result;
	result.source = source;
	XmlNode root;
	XmlParser parser(xml);
	if(!parser.parse(root, result.error)) return result;
	auto catalog = std::make_shared<Catalog>();
	if(!buildCatalog(root, preferredLanguage, source, *catalog, result.error)) return result;
	result.loaded = true;
	result.language = catalog->language;
	result.commands = catalog->commands.size();
	result.features = catalog->features.size();
	result.fields = catalog->fields.size();
	std::atomic_store(&activeCatalog,
		std::static_pointer_cast<const Catalog>(std::move(catalog)));
	return result;
}

ProtocolDefinitionLoadResult loadProtocolDefinitions(const std::filesystem::path& path,
	const string& preferredLanguage)
{
	ProtocolDefinitionLoadResult result;
	const auto utf8Path = path.u8string();
	result.source.assign(reinterpret_cast<const char*>(utf8Path.data()), utf8Path.size());
	std::error_code errorCode;
	const auto size = std::filesystem::file_size(path, errorCode);
	if(errorCode) {
		result.error = "cannot inspect XML catalog: " + errorCode.message();
		return result;
	}
	if(size > MAX_XML_BYTES) {
		result.error = "XML catalog exceeds the 1 MiB safety limit";
		return result;
	}
	std::ifstream input(path, std::ios::binary);
	if(!input) {
		result.error = "cannot open XML catalog";
		return result;
	}
	std::ostringstream contents;
	contents << input.rdbuf();
	if(!input.good() && !input.eof()) {
		result.error = "failed while reading XML catalog";
		return result;
	}
	return loadProtocolDefinitionsXml(contents.str(), preferredLanguage, result.source);
}

void resetProtocolDefinitions() noexcept {
	std::atomic_store(&activeCatalog, std::shared_ptr<const Catalog>());
}

bool findProtocolCommandDefinition(const string& family, const string& command,
	ProtocolCommandDefinition& definition)
{
	const auto catalog = std::atomic_load(&activeCatalog);
	if(!catalog) return false;
	const auto found = catalog->commands.find(key(family, command));
	if(found == catalog->commands.end()) return false;
	definition = found->second;
	return true;
}

bool findProtocolFeatureDefinition(const string& family, const string& feature,
	ProtocolFeatureDefinition& definition, bool ignoreCase)
{
	const auto catalog = std::atomic_load(&activeCatalog);
	if(!catalog) return false;
	if(!ignoreCase) {
		const auto found = catalog->features.find(key(family, feature));
		if(found == catalog->features.end()) return false;
		definition = found->second;
		return true;
	}
	const auto target = asciiLower(feature);
	for(const auto& entry : catalog->features) {
		const auto delimiter = entry.first.find('\x1f');
		if(delimiter != string::npos && entry.first.substr(0, delimiter) == family &&
			asciiLower(entry.first.substr(delimiter + 1)) == target)
		{
			definition = entry.second;
			return true;
		}
	}
	return false;
}

bool findProtocolFieldDefinition(const string& family, const string& command,
	const string& code, ProtocolFieldDefinition& definition, bool includeGlobal)
{
	const auto catalog = std::atomic_load(&activeCatalog);
	if(!catalog) return false;
	auto found = catalog->fields.find(fieldKey(family, command, code));
	if(found == catalog->fields.end() && includeGlobal) {
		found = catalog->fields.find(fieldKey(family, "*", code));
	}
	if(found == catalog->fields.end()) return false;
	definition = found->second;
	return true;
}

} // namespace protocol_analyzer
