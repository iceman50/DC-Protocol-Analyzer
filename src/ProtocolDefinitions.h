/*
* Copyright (C) 2022-2026 iceman50
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*/

#ifndef PROTOCOL_ANALYZER_DEFINITIONS_H
#define PROTOCOL_ANALYZER_DEFINITIONS_H

#include <cstddef>
#include <filesystem>
#include <string>

namespace protocol_analyzer {

struct ProtocolCommandDefinition {
	std::string name;
	std::string category;
	std::string description;
	/** Allowed ADC routing letters. Empty means that the built-in parser decides. */
	std::string routing;
};

struct ProtocolFeatureDefinition {
	std::string name;
	std::string description;
};

struct ProtocolFieldDefinition {
	std::string name;
	std::string description;
};

struct ProtocolDefinitionLoadResult {
	bool loaded = false;
	std::string source;
	std::string language;
	std::string error;
	std::size_t commands = 0;
	std::size_t features = 0;
	std::size_t fields = 0;
};

/**
 * Load and atomically publish a bounded XML definition catalog. A failed load
 * leaves the previously published catalog untouched.
 */
ProtocolDefinitionLoadResult loadProtocolDefinitions(
	const std::filesystem::path& path,
	const std::string& preferredLanguage = "en");

/** In-memory variant used by tests and embedders. */
ProtocolDefinitionLoadResult loadProtocolDefinitionsXml(
	const std::string& xml,
	const std::string& preferredLanguage = "en",
	const std::string& source = "<memory>");

/** Clear XML overrides; the analyzer continues with its compiled-safe fallback. */
void resetProtocolDefinitions() noexcept;

bool findProtocolCommandDefinition(const std::string& family,
	const std::string& command, ProtocolCommandDefinition& definition);
bool findProtocolFeatureDefinition(const std::string& family,
	const std::string& feature, ProtocolFeatureDefinition& definition,
	bool ignoreCase = false);
bool findProtocolFieldDefinition(const std::string& family,
	const std::string& command, const std::string& code,
	ProtocolFieldDefinition& definition, bool includeGlobal = true);

} // namespace protocol_analyzer

#endif
