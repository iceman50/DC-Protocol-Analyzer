/*
 * Focused parser, redaction, and adversarial-input tests.
 */

#include "src/ProtocolAnalyzer.h"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <random>
#include <string>

namespace {

unsigned failures = 0;

void expect(bool condition, const char* message) {
	if(condition) {
		std::cout << "PASS: " << message << '\n';
	} else {
		++failures;
		std::cerr << "FAIL: " << message << '\n';
	}
}

std::string fieldValue(const protocol_analyzer::Result& result,
	const std::string& code)
{
	for(const auto& field : result.fields) {
		if(field.code == code) {
			return field.value;
		}
	}
	return {};
}

std::string fieldName(const protocol_analyzer::Result& result,
	const std::string& code)
{
	for(const auto& field : result.fields) {
		if(field.code == code) {
			return field.name;
		}
	}
	return {};
}

bool hasFieldName(const protocol_analyzer::Result& result,
	const std::string& code, const std::string& name)
{
	for(const auto& field : result.fields) {
		if(field.code == code && field.name == name) {
			return true;
		}
	}
	return false;
}

bool containsSecret(const protocol_analyzer::Result& result,
	const std::string& secret)
{
	if(result.safeMessage.find(secret) != std::string::npos ||
		result.summary.find(secret) != std::string::npos ||
		protocol_analyzer::formatDetails(result).find(secret) != std::string::npos)
	{
		return true;
	}
	for(const auto& field : result.fields) {
		if(field.value.find(secret) != std::string::npos) {
			return true;
		}
	}
	return false;
}

bool isValidUtf8(const std::string& value) {
	for(size_t i = 0; i < value.size();) {
		const auto first = static_cast<unsigned char>(value[i]);
		if(first < 0x80U) {
			++i;
			continue;
		}
		size_t length = 0;
		if(first >= 0xc2U && first <= 0xdfU) {
			length = 2;
		} else if(first >= 0xe0U && first <= 0xefU) {
			length = 3;
		} else if(first >= 0xf0U && first <= 0xf4U) {
			length = 4;
		} else {
			return false;
		}
		if(i + length > value.size()) {
			return false;
		}
		for(size_t j = 1; j < length; ++j) {
			if((static_cast<unsigned char>(value[i + j]) & 0xc0U) != 0x80U) {
				return false;
			}
		}
		const auto second = static_cast<unsigned char>(value[i + 1]);
		if((first == 0xe0U && second < 0xa0U) ||
			(first == 0xedU && second > 0x9fU) ||
			(first == 0xf0U && second < 0x90U) ||
			(first == 0xf4U && second > 0x8fU))
		{
			return false;
		}
		i += length;
	}
	return true;
}

} // namespace

int main() {
	using protocol_analyzer::AnalysisOptions;
	using protocol_analyzer::Status;
	using protocol_analyzer::analyze;
	using protocol_analyzer::analyzeBinaryPayload;

	const auto binf = analyze("ADC",
		"BINF ABCD NIalice DEFriendly\\suser SS1073741824 SF42000 SL3");
	expect(binf.command == "BINF" && binf.action == "INF",
		"ADC routing prefix and action are decoded independently");
	expect(binf.routing == "Broadcast" && binf.category == "Identity",
		"BINF routing and category are classified");
	expect(fieldValue(binf, "NI") == "alice" &&
		fieldValue(binf, "DE") == "Friendly user",
		"ADC named fields and escaping are decoded");
	expect(binf.summary.find("1.00 GiB") != std::string::npos &&
		binf.summary.find("42000 files") != std::string::npos,
		"BINF summary formats share metadata");

	const auto iinf = analyze("ADC", "IINF CT32 NIExample\\sHub");
	expect(iinf.command == "IINF" && iinf.routing == "From hub",
		"IINF is recognized as hub-originated information");
	expect(fieldValue(iinf, "CT") == "32 (Hub)" &&
		fieldValue(iinf, "CT.hub") == "Set" &&
		iinf.summary.find("type 32 (Hub)") != std::string::npos,
		"ADC INF identifies the hub client type");
	const auto adcClientTypes = analyze("ADC", "BINF ABCD CT127 NIservice");
	expect(adcClientTypes.status == Status::Valid &&
		fieldValue(adcClientTypes, "CT") ==
			"127 (Bot, Registered user, Operator, Super user, Hub owner, Hub, Hidden)" &&
		fieldValue(adcClientTypes, "CT.bot") == "Set" &&
		fieldValue(adcClientTypes, "CT.registered") == "Set" &&
		fieldValue(adcClientTypes, "CT.operator") == "Set" &&
		fieldValue(adcClientTypes, "CT.super") == "Set" &&
		fieldValue(adcClientTypes, "CT.owner") == "Set" &&
		fieldValue(adcClientTypes, "CT.hub") == "Set" &&
		fieldValue(adcClientTypes, "CT.hidden") == "Set",
		"ADC INF decodes every documented additive client-type flag");
	const auto ordinaryAdcClient = analyze("ADC", "BINF ABCD CT0 NIuser");
	expect(ordinaryAdcClient.status == Status::Valid &&
		fieldValue(ordinaryAdcClient, "CT") == "0 (No client-type flags)",
		"ADC INF accepts an ordinary client with no type flags");
	const auto futureAdcClientType = analyze("ADC", "BINF ABCD CT128 NIuser");
	const auto malformedAdcClientType = analyze("ADC", "BINF ABCD CTbot NIuser");
	expect(futureAdcClientType.status == Status::Warning &&
		fieldValue(futureAdcClientType, "CT.unknown") == "128" &&
		malformedAdcClientType.status == Status::Invalid,
		"ADC INF preserves unknown client-type bits and rejects malformed CT values");
	const auto csup = analyze("ADC", "CSUP ADBASE ADTIGR");
	expect(csup.command == "CSUP" && csup.routing == "Client-to-client TCP" &&
		csup.fields.size() == 2,
		"CSUP feature negotiation is decoded");
	expect(fieldName(csup, "AD").find("ADC base protocol") != std::string::npos,
		"ADC SUP feature codes are identified by extension name");
	const auto rtf0Support = analyze("ADC", "ISUP ADRTF0");
	expect(rtf0Support.status == Status::Valid &&
		fieldValue(rtf0Support, "AD") == "RTF0" &&
		fieldName(rtf0Support, "AD").find("Rich-text chat messages") !=
			std::string::npos,
		"ADC SUP detects the RTF0 rich-text chat extension");
	const auto hsup = analyze("ADC", "HSUP ADBASE RMZLIF");
	expect(hsup.command == "HSUP" && hsup.routing == "To hub",
		"HSUP routing is decoded");
	const auto outgoingKeepAlive = analyze("ADC", "\n");
	expect(outgoingKeepAlive.command == "KEEPALIVE" &&
		outgoingKeepAlive.category == "Control" &&
		outgoingKeepAlive.status == Status::Valid &&
		outgoingKeepAlive.warnings.empty() &&
		outgoingKeepAlive.safeMessage == "\\n",
		"ADC line-feed keep-alive is valid and visibly classified");
	const auto incomingKeepAlive = analyze("ADC", "");
	expect(incomingKeepAlive.command == "KEEPALIVE" &&
		incomingKeepAlive.status == Status::Valid,
		"delimiter-stripped incoming ADC keep-alive is valid");
	const auto invalidCarriageReturn = analyze("ADC", "\r");
	expect(invalidCarriageReturn.status == Status::Invalid,
		"non-ADC carriage-return frame remains invalid");
	const auto ctm = analyze("ADC", "DCTM ABCD EFGH ADC/1.0 1511 token");
	expect(ctm.status == Status::Valid && fieldValue(ctm, "port") == "1511",
		"DCTM header and positional parameters are decoded");
	const auto extendedCtm = analyze("ADC",
		"DCTM ABCD EFGH ADC/1.0 1511 token PRvendor");
	expect(fieldValue(extendedCtm, "PR") == "vendor" &&
		extendedCtm.status == Status::Valid,
		"ADC CTM accepts and preserves trailing named extension fields");
	const auto extendedRcm = analyze("ADC",
		"CRCM ADC/1.0 token XXvendor");
	expect(fieldValue(extendedRcm, "XX") == "vendor" &&
		extendedRcm.status == Status::Valid,
		"ADC RCM accepts and preserves trailing named extension fields");
	const auto adcExtensions = analyze("ADC",
		"BINF ABCD SUTCP4,NAT0,ASCH,SUD1,ADC0,ADCS,RTF0");
	expect(fieldValue(adcExtensions, "SU").find("NAT traversal revision 0") !=
			std::string::npos &&
		fieldValue(adcExtensions, "SU").find(
			"Legacy ADC-over-TLS capability (ADCS/0.10)") != std::string::npos &&
		fieldValue(adcExtensions, "SU").find("Advanced search") !=
			std::string::npos &&
		fieldValue(adcExtensions, "SU").find("Rich-text chat messages") !=
			std::string::npos,
		"ADC INF support lists use protocol meanings rather than vendor attribution");
	const auto richTextMessage = analyze("ADC",
		"BMSG ABCD ![a\\scat](https://example.org/cat.png) RT1");
	expect(richTextMessage.status == Status::Valid &&
		fieldValue(richTextMessage, "text") ==
			"![a cat](https://example.org/cat.png)" &&
		fieldValue(richTextMessage, "RT") == "1" &&
		hasFieldName(richTextMessage, "RT", "Rich-text formatting (RTF0)") &&
		richTextMessage.summary.find("rich-text chat") != std::string::npos,
		"ADC RTF0 RT1 messages are identified as rich-text chat");
	const auto rtf0FeatureCast = analyze("ADC",
		"FMSG ABCD +RTF0 Hello RT1");
	expect(rtf0FeatureCast.status == Status::Valid &&
		rtf0FeatureCast.routing == "Feature broadcast" &&
		fieldName(rtf0FeatureCast, "+").find("Rich-text chat messages") !=
			std::string::npos &&
		hasFieldName(rtf0FeatureCast, "RT", "Rich-text formatting (RTF0)"),
		"ADC RTF0 feature-broadcast messages decode their route and RT flag");
	const auto disabledRichTextFlag = analyze("ADC", "BMSG ABCD Plain RT0");
	expect(disabledRichTextFlag.status == Status::Valid &&
		disabledRichTextFlag.summary.find("rich-text") == std::string::npos,
		"ADC RTF0 RT0 does not classify a message as rich text");
	const auto hubInfFields = analyze("ADC",
		"IINF MS1024 MR1 MO2 MU3 XU6 FOadc://backup.example UP3600");
	expect(hasFieldName(hubInfFields, "MS", "Minimum share") &&
		hasFieldName(hubInfFields, "MR", "Minimum registered hubs") &&
		hasFieldName(hubInfFields, "FO", "Failover hub addresses") &&
		hasFieldName(hubInfFields, "UP", "Hub uptime"),
		"ADC PING INF field codes use their INF-specific meanings");
	const auto adcResultFields = analyze("ADC",
		"DRES ABCD EFGH FNfile.txt SI42 SL2 FI4 FO3 DM1700000000");
	expect(hasFieldName(adcResultFields, "SL", "Slots currently available") &&
		hasFieldName(adcResultFields, "FI", "Recursive file count") &&
		hasFieldName(adcResultFields, "FO", "Recursive folder count") &&
		hasFieldName(adcResultFields, "DM", "Modified time"),
		"ADC RES fields include standard and deployed command-specific meanings");
	const auto adcListGet = analyze("ADC",
		"CGET list /Shared/ 0 -1 RE1 TL1 IDABCD DB42");
	expect(adcListGet.status == Status::Valid &&
		hasFieldName(adcListGet, "RE", "Recursive file-list request") &&
		hasFieldName(adcListGet, "TL", "TTH list requested") &&
		hasFieldName(adcListGet, "ID", "Requester SID") &&
		hasFieldName(adcListGet, "DB", "Downloaded and verified bytes"),
		"ADC list GET resolves and validates its request fields");
	const auto adcFileGet = analyze("ADC",
		"CGET file TTH/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 666 333 ZL1");
	expect(adcFileGet.status == Status::Valid &&
		hasFieldName(adcFileGet, "ZL", "Compressed transfer requested"),
		"ADC file GET accepts concrete nonnegative ranges");
	const auto adcListSend = analyze("ADC",
		"CSND list /Shared/ 0 42 TL1");
	expect(adcListSend.status == Status::Valid &&
		hasFieldName(adcListSend, "TL", "TTH list included"),
		"ADC SND TL reports that a TTH list is included");
	const auto bloomGet = analyze("ADC",
		"IGET blom / 0 92408 BK8 BH24");
	expect(bloomGet.status == Status::Valid &&
		bloomGet.command == "IGET" &&
		bloomGet.name == "Bloom filter request" &&
		hasFieldName(bloomGet, "BK", "Bloom sub-hash count (k)") &&
		hasFieldName(bloomGet, "BH", "Bloom sub-hash width (h, bits)") &&
		fieldValue(bloomGet, "m") == "739264" &&
		!bloomGet.binaryPayloadFollows &&
		bloomGet.binaryPayloadType == "blom",
		"ADC BLOM IGET request decodes k, h, and the derived filter bit size");
	const auto bloomSend = analyze("ADC",
		"HSND blom / 0 92408 BK8\n");
	expect(bloomSend.status == Status::Valid &&
		bloomSend.command == "HSND" &&
		bloomSend.name == "Bloom filter response" &&
		hasFieldName(bloomSend, "BK", "Bloom sub-hash count (k, echoed)") &&
		bloomSend.binaryPayloadFollows &&
		bloomSend.expectedBinaryPayloadBytes == 92408 &&
		bloomSend.binaryPayloadType == "blom" &&
		bloomSend.summary.find("binary bytes follow") != std::string::npos,
		"ADC BLOM HSND exposes the exact following opaque-payload byte count");
	const auto emptyBloomSend = analyze("ADC", "HSND blom / 0 0 BK8");
	expect(emptyBloomSend.status == Status::Valid &&
		!emptyBloomSend.binaryPayloadFollows &&
		emptyBloomSend.expectedBinaryPayloadBytes == 0,
		"zero-length BLOM responses do not announce a following payload");
	const auto wrongBloomRoutes = analyze("ADC",
		"HGET blom / 0 92408 BK8 BH24");
	const auto wrongBloomResponseRoute = analyze("ADC",
		"ISND blom / 0 92408 BK8");
	const auto wrongBloomCase = analyze("ADC",
		"HSND BLOM / 0 92408 BK8");
	expect(wrongBloomRoutes.status == Status::Invalid &&
		wrongBloomResponseRoute.status == Status::Invalid &&
		wrongBloomCase.status == Status::Invalid &&
		wrongBloomCase.binaryPayloadFollows,
		"BLOM enforces IGET/HSND routing and the exact lowercase transfer type");
	const auto malformedBloomShape = analyze("ADC",
		"IGET blom wrong 1 92409 BK8 BH24");
	const auto missingBloomParameters = analyze("ADC",
		"IGET blom / 0 92408");
	const auto invalidBloomK = analyze("ADC",
		"IGET blom / 0 92408 BK9 BH24");
	const auto invalidBloomH = analyze("ADC",
		"IGET blom / 0 92408 BK8 BH65");
	const auto invalidBloomM = analyze("ADC",
		"IGET blom / 0 16 BK1 BH7");
	const auto repeatedBloomField = analyze("ADC",
		"IGET blom / 0 92408 BK8 BK8 BH24");
	expect(malformedBloomShape.status == Status::Invalid &&
		missingBloomParameters.status == Status::Invalid &&
		invalidBloomK.status == Status::Invalid &&
		invalidBloomH.status == Status::Invalid &&
		invalidBloomM.status == Status::Invalid &&
		repeatedBloomField.status == Status::Invalid,
		"BLOM validates namespace, start, m, k, h, and unique request fields");
	const auto bloomPayload = analyzeBinaryPayload("ADC", "blom", 92408, 92408);
	expect(bloomPayload.binaryPayload &&
		!bloomPayload.binaryPayloadFollows &&
		bloomPayload.observedBinaryPayloadBytes == 92408 &&
		bloomPayload.expectedBinaryPayloadBytes == 92408 &&
		bloomPayload.safeMessage ==
			"<92408-byte BLOM payload omitted>" &&
		protocol_analyzer::formatDetails(bloomPayload).find(
			"Opaque binary (not decoded as text)") != std::string::npos,
		"correlated BLOM bytes produce an ASCII-only opaque payload result");
	const auto shortBloomPayload =
		analyzeBinaryPayload("ADC", "blom", 100, 92408);
	expect(shortBloomPayload.status == Status::Warning,
		"correlated binary payload size mismatches are visible without decoding bytes");
	const auto unmeasuredBloomPayload =
		analyzeBinaryPayload("ADC", "blom", 92408);
	expect(unmeasuredBloomPayload.status == Status::Valid &&
		unmeasuredBloomPayload.binaryPayload &&
		!unmeasuredBloomPayload.observedBinaryPayloadBytesKnown &&
		unmeasuredBloomPayload.expectedBinaryPayloadBytes == 92408 &&
		fieldValue(unmeasuredBloomPayload, "observed") ==
			"Unavailable from host hook" &&
		unmeasuredBloomPayload.summary.find("observed size unavailable") !=
			std::string::npos,
		"opaque BLOM results distinguish unavailable host lengths from zero bytes");
	const auto invalidAdcRecursiveFile = analyze("ADC",
		"CGET file TTH/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 0 -1 RE1");
	expect(invalidAdcRecursiveFile.status == Status::Invalid,
		"ADC rejects RE on non-list GET transfers");
	const auto invalidAdcTthListFile = analyze("ADC",
		"CSND file TTH/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 0 42 TL1");
	expect(invalidAdcTthListFile.status == Status::Invalid,
		"ADC rejects TL on non-list SND transfers");
	const auto invalidAdcFlags = analyze("ADC",
		"CGET list /Shared/ 0 -1 RE0 TL0 ZL0");
	expect(invalidAdcFlags.status == Status::Invalid,
		"ADC transfer flags require the exact value 1");
	const auto invalidAdcRequesterId = analyze("ADC",
		"CGET list /Shared/ 0 -1 IDABC1");
	const auto invalidAdcDownloadedBytes = analyze("ADC",
		"CGET list /Shared/ 0 -1 DB-1");
	expect(invalidAdcRequesterId.status == Status::Invalid &&
		invalidAdcDownloadedBytes.status == Status::Invalid,
		"ADC GET validates requester SID and downloaded-byte fields");
	const auto invalidAdcSendGetFields = analyze("ADC",
		"CSND list /Shared/ 0 42 IDABCD DB42");
	expect(invalidAdcSendGetFields.status == Status::Invalid &&
		hasFieldName(invalidAdcSendGetFields, "ID",
			"Requester SID (GET-only)") &&
		hasFieldName(invalidAdcSendGetFields, "DB",
			"Downloaded and verified bytes (GET-only)"),
		"ADC SND rejects and labels GET-only ID and DB fields");
	const auto invalidAdcListIdentifier = analyze("ADC",
		"CGET list Shared 0 -1");
	const auto invalidAdcListStart = analyze("ADC",
		"CGET list /Shared/ 1 -1");
	const auto invalidAdcStart = analyze("ADC",
		"CGET file TTH/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA -1 42");
	const auto invalidAdcGetCount = analyze("ADC",
		"CGET file TTH/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 0 -2");
	const auto invalidAdcSendCount = analyze("ADC",
		"CSND file TTH/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 0 -1");
	expect(invalidAdcListIdentifier.status == Status::Invalid &&
		invalidAdcListStart.status == Status::Invalid &&
		invalidAdcStart.status == Status::Invalid &&
		invalidAdcGetCount.status == Status::Invalid &&
		invalidAdcSendCount.status == Status::Invalid,
		"ADC validates list paths, start positions, and GET/SND byte counts");
	const auto adcQuit = analyze("ADC", "IQUI ABCD IDWXYZ RDadc://next.example");
	expect(hasFieldName(adcQuit, "ID", "Disconnect initiator SID") &&
		hasFieldName(adcQuit, "RD", "Redirect URL"),
		"ADC QUI fields do not inherit INF meanings");
	const auto adcCommand = analyze("ADC",
		"ICMD Tools/Test CT4 CO1 TTMSG\\s+test");
	expect(hasFieldName(adcCommand, "CT", "Command context") &&
		hasFieldName(adcCommand, "CO", "Constrained execution"),
		"ADC CMD fields use user-command meanings");
	const auto adcCinf = analyze("ADC", "CINF PM1 CO3");
	expect(hasFieldName(adcCinf, "PM", "Private-message connection") &&
		hasFieldName(adcCinf, "CO", "Connection count"),
		"ADC CINF resolves CCPM and MCN1 field collisions");
	const auto onlineIdentity = analyze("ADC",
		"BOID ABCD LoL SUtest SEkr");
	expect(fieldValue(onlineIdentity, "service") == "LoL" &&
		hasFieldName(onlineIdentity, "SU", "Summoner name") &&
		hasFieldName(onlineIdentity, "SE", "Region") &&
		fieldValue(onlineIdentity, "SU") == "test",
		"ADC OID applies field labels documented for its known service");
	const auto unknownOnlineIdentity = analyze("ADC",
		"BOID ABCD VendorService SUaccount SEzone");
	expect(hasFieldName(unknownOnlineIdentity, "SU", "Service-specific field") &&
		hasFieldName(unknownOnlineIdentity, "SE", "Service-specific field") &&
		fieldValue(unknownOnlineIdentity, "SU") == "account",
		"ADC OID leaves unknown-service fields generic");
	const auto onlineIdentityRequest = analyze("ADC", "HOIR mslive");
	expect(fieldValue(onlineIdentityRequest, "service") == "mslive",
		"ADC OIR decodes its required positional service");
	const auto onlineIdentityResponse = analyze("ADC",
		"BOIR ABCD Google EMexample@gmail.com");
	expect(fieldValue(onlineIdentityResponse, "service") == "Google" &&
		hasFieldName(onlineIdentityResponse, "EM", "Email address"),
		"ADC OIR response decodes known service-specific response fields");
	const auto missingInfField = analyze("ADC",
		"ISTA 241 Missing\\sINF\\sfield FMNI FBID FCINF");
	expect(hasFieldName(missingInfField, "FM", "Missing required INF field") &&
		hasFieldName(missingInfField, "FB", "Invalid INF field"),
		"ADC STA decodes missing and invalid INF field identifiers");
	const auto nat = analyze("ADC",
		"DNAT ABCD EFGH ADC/1.0 1511 traversal-token");
	expect(nat.known && nat.category == "Connection" &&
		fieldValue(nat, "port") == "1511",
		"ADC NATT NAT command is structurally decoded");
	const auto typing = analyze("ADC", "FTPN ABCD +TYPE 11");
	expect(typing.known && typing.category == "Chat" &&
		fieldValue(typing, "state") == "11",
		"ADC TYPE typing notification is detected");
	const std::string adcCid(39, 'A');
	const auto partial = analyze("ADC",
		"UPSR " + adcCid + " HIexample.org:1511 U40 TR" + adcCid +
		" PC1 PI0,1");
	expect(partial.known && partial.category == "Transfer" &&
		fieldValue(partial, "PI") == "0,1",
		"ADC PFSR partial-file command is detected");
	const auto airDcTcp = analyze("ADC",
		"ITCP I4192.0.2.10 P41511 TOreachability-token");
	expect(airDcTcp.known && airDcTcp.category == "Connection" &&
		fieldValue(airDcTcp, "P4") == "1511",
		"AirDC HBRI TCP command is detected");
	const auto airDcPmi = analyze("ADC", "CPMI SN1 TP1");
	expect(airDcPmi.known && airDcPmi.category == "Chat" &&
		fieldValue(airDcPmi, "TP") == "1",
		"AirDC private-message information command is detected");
	const auto airDcBundle = analyze("ADC",
		"UPBD " + adcCid + " HIexample.org:1511 BU42 TH" + adcCid + " RE1");
	expect(airDcBundle.known && airDcBundle.category == "Transfer" &&
		fieldValue(airDcBundle, "BU") == "42",
		"AirDC partial-bundle command is detected");

	const std::string privateId = "THISPRIVATEIDMUSTNOTLEAK";
	const auto privateInf = analyze("ADC",
		"HINF IDPUBLIC PD" + privateId + " NIalice");
	expect(privateInf.sensitive && !containsSecret(privateInf, privateId),
		"ADC private ID is redacted from every presentation surface");
	expect(privateInf.safeMessage.find("PD<redacted>") != std::string::npos,
		"ADC private-ID field structure remains visible after redaction");
	AnalysisOptions diagnosticOptions;
	diagnosticOptions.redactSensitiveValues = false;
	const auto visiblePrivateInf = analyze("ADC",
		"HINF IDPUBLIC PD" + privateId + " NIalice", diagnosticOptions);
	expect(visiblePrivateInf.sensitive && !visiblePrivateInf.redactionEnabled &&
		fieldValue(visiblePrivateInf, "PD") == privateId &&
		visiblePrivateInf.safeMessage.find(privateId) != std::string::npos &&
		protocol_analyzer::formatDetails(visiblePrivateInf).find(
			"Raw (redaction disabled):") != std::string::npos,
		"diagnostic analysis exposes ADC sensitive values when redaction is disabled");

	const std::string pasSecret = "PASSWORDRESPONSEHASH";
	const auto pas = analyze("ADC", "HPAS " + pasSecret);
	expect(pas.sensitive && !containsSecret(pas, pasSecret),
		"ADC password response is redacted");
	const std::string pasMetadata = "PAS_EXTENSION_SECRET";
	const auto extendedPas = analyze("ADC",
		"HPAS " + pasSecret + " XX" + pasMetadata);
	expect(extendedPas.status == Status::Valid &&
		!containsSecret(extendedPas, pasSecret) &&
		!containsSecret(extendedPas, pasMetadata) &&
		fieldValue(extendedPas, "XX") == "<redacted>",
		"ADC PAS accepts named extension fields while redacting their values");
	const std::string sudpKey = "SUDPKEYMUSTNOTLEAK";
	const auto encryptedSearch = analyze("ADC",
		"USCH " + adcCid + " TR" + adcCid + " KY" + sudpKey);
	expect(encryptedSearch.sensitive && !containsSecret(encryptedSearch, sudpKey) &&
		encryptedSearch.safeMessage.find("KY<redacted>") != std::string::npos,
		"ADC SUDP encryption keys are redacted from every presentation surface");

	const auto badEscape = analyze("ADC", "IINF NIbroken\\");
	expect(badEscape.status == Status::Invalid,
		"incomplete ADC escape sequence is invalid");
	const auto badSid = analyze("ADC", "BINF bad! NIalice");
	expect(badSid.status == Status::Invalid,
		"invalid ADC SID is rejected by validation");
	const auto unknownAdc = analyze("ADC", "BXYZ ABCD AAvalue");
	expect(!unknownAdc.known && unknownAdc.status == Status::Warning &&
		unknownAdc.safeMessage.find("BXYZ") != std::string::npos,
		"unknown ADC actions are preserved with a warning");
	const auto positionalAdc = analyze("ADC", "HXYZ /vendor/path plain\\svalue");
	expect(!positionalAdc.known && positionalAdc.status == Status::Warning &&
		fieldValue(positionalAdc, "arg1") == "/vendor/path",
		"unknown ADC actions preserve positional extension parameters");

	const std::string batchedAdcSecret = "BATCHED_ADC_SECRET";
	const auto batchedAdc = analyze("ADC",
		"IINF NIhub\r\nHPAS " + batchedAdcSecret + "\r\n");
	expect(!containsSecret(batchedAdc, batchedAdcSecret),
		"credential scanning redacts additional ADC frames defensively");

	const std::string password = "correct horse battery staple";
	const auto myPass = analyze("NMDC", "$MyPass " + password + "|");
	expect(myPass.command == "$MyPass" && myPass.sensitive &&
		!containsSecret(myPass, password),
		"NMDC password is redacted from table, details, and fields");
	expect(myPass.safeMessage == "$MyPass <redacted>|",
		"NMDC password redaction preserves command framing");
	const auto visibleMyPass = analyze("NMDC", "$MyPass " + password + "|",
		diagnosticOptions);
	expect(visibleMyPass.sensitive && !visibleMyPass.redactionEnabled &&
		fieldValue(visibleMyPass, "secret") == password &&
		visibleMyPass.safeMessage == "$MyPass " + password + "|" &&
		visibleMyPass.summary.find("visible") != std::string::npos &&
		containsSecret(visibleMyPass, password),
		"diagnostic analysis exposes NMDC authentication values when redaction is disabled");
	const std::string batchedNmdcSecret = "BATCHED_NMDC_SECRET";
	const auto batchedNmdc = analyze("NMDC",
		"$Hello alice|$MyPass " + batchedNmdcSecret + "|");
	expect(!containsSecret(batchedNmdc, batchedNmdcSecret) &&
		batchedNmdc.safeMessage.find("$MyPass <redacted>|") != std::string::npos,
		"credential scanning redacts additional NMDC frames defensively");
	const auto nmdcKeepAlive = analyze("NMDC", "|");
	expect(nmdcKeepAlive.command == "KEEPALIVE" &&
		nmdcKeepAlive.name == "Keep-alive" &&
		nmdcKeepAlive.category == "Control" &&
		nmdcKeepAlive.routing == "Connection" &&
		nmdcKeepAlive.status == Status::Valid &&
		nmdcKeepAlive.warnings.empty() &&
		nmdcKeepAlive.summary == "NMDC keep-alive" &&
		nmdcKeepAlive.safeMessage == "|",
		"NMDC delimiter-only keep-alive is valid and visibly classified");

	const auto myInfo = analyze("NMDC",
		"$MyINFO $ALL alice <++ V:0.881,M:A,H:1/0/0,S:3>$ "
		"$LAN(T3)1$alice@example.invalid$1073741824$|");
	expect(myInfo.command == "$MyINFO" && fieldValue(myInfo, "nick") == "alice",
		"NMDC MyINFO nickname is decoded");
	expect(myInfo.summary.find("1.00 GiB") != std::string::npos,
		"NMDC MyINFO share size is summarized");
	expect(fieldValue(myInfo, "connection") == "LAN(T3)" &&
		fieldValue(myInfo, "status") == "49 (0x31)" &&
		fieldValue(myInfo, "status.normal") == "Set" &&
		fieldValue(myInfo, "status.tls") == "Set" &&
		fieldValue(myInfo, "status.nat") == "Set",
		"NMDC MyINFO separates and decodes its combined status byte");

	auto myInfoWithStatus = [](unsigned char status) {
		std::string message =
			"$MyINFO $ALL status-user Test$ $LAN(T3)";
		message.push_back(static_cast<char>(status));
		message += "$status@example.invalid$42$|";
		return protocol_analyzer::analyze("NMDC", message);
	};
	const auto everyNmdcStatus = myInfoWithStatus(0xffU);
	expect(everyNmdcStatus.status == Status::Valid &&
		fieldValue(everyNmdcStatus, "status") == "255 (0xFF)" &&
		fieldValue(everyNmdcStatus, "status.normal") == "Set" &&
		fieldValue(everyNmdcStatus, "status.away") == "Set" &&
		fieldValue(everyNmdcStatus, "status.server") == "Set" &&
		fieldValue(everyNmdcStatus, "status.fireball") == "Set" &&
		fieldValue(everyNmdcStatus, "status.tls") == "Set" &&
		fieldValue(everyNmdcStatus, "status.nat") == "Set" &&
		fieldValue(everyNmdcStatus, "status.ipv4") == "Set" &&
		fieldValue(everyNmdcStatus, "status.ipv6") == "Set",
		"NMDC MyINFO detects every documented status and capability bit");
	const auto whitespaceNmdcStatus = myInfoWithStatus(0x20U);
	expect(whitespaceNmdcStatus.status == Status::Valid &&
		fieldValue(whitespaceNmdcStatus, "connection") == "LAN(T3)" &&
		fieldValue(whitespaceNmdcStatus, "status") == "32 (0x20)" &&
		fieldValue(whitespaceNmdcStatus, "status.nat") == "Set" &&
		fieldValue(whitespaceNmdcStatus, "status.normal").empty(),
		"NMDC MyINFO preserves and decodes a whitespace-valued status byte");

	const auto search = analyze("NMDC",
		"$Search 192.0.2.1:412 T?T?500000?1?Linux$ISO|");
	expect(search.command == "$Search" &&
		fieldValue(search, "pattern") == "Linux ISO",
		"NMDC active search structure decodes dollar word separators");
	const auto literalDollarSearch = analyze("NMDC",
		"$Search Hub:alice F?F?0?1?cost&#36;value|");
	expect(fieldValue(literalDollarSearch, "pattern") == "cost$value",
		"NMDC search decoding preserves escaped literal dollar signs");
	const auto linkedSearch = analyze("NMDC",
		"$MultiSearch 192.0.2.1:412 F?F?0?1?manual|");
	expect(linkedSearch.known && linkedSearch.category == "Search",
		"documented linked-hub NMDC commands are classified");
	const std::string shortTth(39, 'A');
	const auto shortActive = analyze("NMDC",
		"$SA " + shortTth + " 192.0.2.1:412|");
	expect(shortActive.known && shortActive.status == Status::Valid &&
		fieldValue(shortActive, "endpoint") == "192.0.2.1:412",
		"NMDC TTHS short active search is decoded");
	const auto shortPassive = analyze("NMDC",
		"$SP " + shortTth + " alice|");
	expect(shortPassive.known && fieldValue(shortPassive, "nick") == "alice",
		"NMDC TTHS short passive search is decoded");
	const auto operatorCommand = analyze("NMDC", "$SetTopic Protocol testing|");
	expect(operatorCommand.known && operatorCommand.category == "Hub",
		"documented operator extension commands are classified");
	const auto nickRule = analyze("NMDC",
		"$NickRule Min 3$$Max 64$$Char 32 60 62$$Pref [ISP]|");
	expect(nickRule.known && fieldValue(nickRule, "Min") == "3" &&
		fieldValue(nickRule, "Pref") == "[ISP]",
		"NMDC nickname-rule extension is decoded");
	const auto searchRule = analyze("NMDC",
		"$SearchRule Min 3$$Max 256$$Num 1$$Int 4$$IntPas 6$$Share 1024|");
	expect(searchRule.known && fieldValue(searchRule, "IntPas") == "6" &&
		fieldValue(searchRule, "Share") == "1024",
		"NMDC search-rule extension is decoded");
	const auto badNick = analyze("NMDC", "$BadNick Pref [ISP1] [ISP2]|");
	expect(badNick.known && badNick.category == "Status" &&
		fieldValue(badNick, "Pref") == "[ISP1] [ISP2]",
		"NMDC nickname-rule violation is decoded");
	const auto hubLogo = analyze("NMDC",
		"$SetLogo https://example.invalid/hub-logo.png|");
	expect(hubLogo.known && fieldValue(hubLogo, "url").find("https://") == 0,
		"NMDC hub-logo extension is decoded without fetching its URL");
	const auto hubUrl = analyze("NMDC", "$MyHubURL hub.example:411|");
	expect(hubUrl.known && fieldValue(hubUrl, "url") == "hub.example:411",
		"NMDC HubURL response is decoded");
	const auto nmdcSupports = analyze("NMDC",
		"$Supports ADCGet TTHS NickRule SearchRule HubURL ZPipe0|");
	expect(nmdcSupports.known &&
		fieldName(nmdcSupports, "feature").find("ADC-style transfers") !=
			std::string::npos &&
		nmdcSupports.summary.find("6 recognized") != std::string::npos,
		"NMDC support tokens are identified by extension name");
	const auto nmdcNetworkSupports = analyze("NMDC", "$Supports IP64 TLS|");
	expect(fieldName(nmdcNetworkSupports, "feature").find(
			"IPv6 capability and dual-address reporting") != std::string::npos &&
		protocol_analyzer::formatDetails(nmdcNetworkSupports).find(
			"TLS-encrypted client-to-client connections") != std::string::npos,
		"NMDC IP64 and TLS feature names describe their actual capabilities");

	const auto adcGet = analyze("NMDC",
		"$ADCGET list /Shared\\sFiles/ 0 -1 RE1 TL1 IDABCD DB42|");
	expect(adcGet.command == "$ADCGET" &&
		adcGet.status == Status::Valid &&
		fieldValue(adcGet, "identifier") == "/Shared Files/" &&
		hasFieldName(adcGet, "RE", "Recursive file-list request") &&
		hasFieldName(adcGet, "TL", "TTH list requested") &&
		hasFieldName(adcGet, "DB", "Downloaded and verified bytes"),
		"NMDC ADCGET parses ADC-escaped identifiers without shifting fields");
	const auto legacyEscapedAdcGet = analyze("NMDC",
		"$ADCGET list /Legacy\\ Folder/ 0 -1 RE1|");
	expect(legacyEscapedAdcGet.status == Status::Valid &&
		fieldValue(legacyEscapedAdcGet, "identifier") == "/Legacy Folder/" &&
		fieldValue(legacyEscapedAdcGet, "start") == "0",
		"NMDC ADCGET accepts the deployed legacy backslash-space escape");
	const auto escapedControlAdcGet = analyze("NMDC",
		"$ADCGET list /Line\\nName\\\\Path/ 0 -1|");
	expect(escapedControlAdcGet.status == Status::Valid &&
		fieldValue(escapedControlAdcGet, "identifier") ==
			"/Line\\nName\\Path/",
		"NMDC ADCGET decodes ADC newline and backslash escapes");
	const auto adcGetNoHtmlDecode = analyze("NMDC",
		"$ADCGET file TTH/abc&#36;def 0 -1 ZL1|");
	expect(fieldValue(adcGetNoHtmlDecode, "identifier") ==
			"TTH/abc&#36;def" &&
		hasFieldName(adcGetNoHtmlDecode, "ZL", "Compressed transfer requested"),
		"NMDC ADCGET uses ADC escaping and does not apply NMDC HTML decoding");
	const auto adcSend = analyze("NMDC",
		"$ADCSND list /Shared\\sFiles/ 0 42 TL1|");
	expect(adcSend.status == Status::Valid &&
		hasFieldName(adcSend, "TL", "TTH list included"),
		"NMDC ADCSND TL reports that a TTH list is included");
	const auto invalidNmdcRecursiveFile = analyze("NMDC",
		"$ADCGET file TTH/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA "
		"0 -1 RE1|");
	expect(invalidNmdcRecursiveFile.status == Status::Invalid,
		"NMDC ADCGET rejects RE on non-list transfers");
	const auto invalidNmdcTthListFile = analyze("NMDC",
		"$ADCSND file TTH/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA "
		"0 42 TL1|");
	expect(invalidNmdcTthListFile.status == Status::Invalid,
		"NMDC ADCSND rejects TL on non-list transfers");
	const auto invalidNmdcFlags = analyze("NMDC",
		"$ADCGET list /Shared/ 0 -1 RE0 TL0 ZL0|");
	expect(invalidNmdcFlags.status == Status::Invalid,
		"NMDC ADC transfer flags require the exact value 1");
	const auto invalidNmdcRequesterId = analyze("NMDC",
		"$ADCGET list /Shared/ 0 -1 IDABC1|");
	const auto invalidNmdcDownloadedBytes = analyze("NMDC",
		"$ADCGET list /Shared/ 0 -1 DBnot-a-number|");
	expect(invalidNmdcRequesterId.status == Status::Invalid &&
		invalidNmdcDownloadedBytes.status == Status::Invalid,
		"NMDC ADCGET validates requester SID and downloaded-byte fields");
	const auto invalidNmdcSendGetFields = analyze("NMDC",
		"$ADCSND list /Shared/ 0 42 IDABCD DB42|");
	expect(invalidNmdcSendGetFields.status == Status::Invalid &&
		hasFieldName(invalidNmdcSendGetFields, "ID",
			"Requester SID (ADCGET-only)") &&
		hasFieldName(invalidNmdcSendGetFields, "DB",
			"Downloaded and verified bytes (ADCGET-only)"),
		"NMDC ADCSND rejects and labels ADCGET-only ID and DB fields");
	const auto invalidNmdcListIdentifier = analyze("NMDC",
		"$ADCGET list Shared 0 -1|");
	const auto invalidNmdcListStart = analyze("NMDC",
		"$ADCGET list /Shared/ 1 -1|");
	const auto invalidNmdcStart = analyze("NMDC",
		"$ADCGET file TTH/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA -1 42|");
	const auto invalidNmdcGetCount = analyze("NMDC",
		"$ADCGET file TTH/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 0 -2|");
	const auto invalidNmdcSendCount = analyze("NMDC",
		"$ADCSND file TTH/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 0 -1|");
	expect(invalidNmdcListIdentifier.status == Status::Invalid &&
		invalidNmdcListStart.status == Status::Invalid &&
		invalidNmdcStart.status == Status::Invalid &&
		invalidNmdcGetCount.status == Status::Invalid &&
		invalidNmdcSendCount.status == Status::Invalid,
		"NMDC validates list paths, start positions, and ADCGET/ADCSND counts");

	const auto privateMessage = analyze("NMDC",
		"$To: john From: peter $<peter> dogs are cute|");
	expect(privateMessage.command == "$To:" &&
		fieldValue(privateMessage, "target") == "john" &&
		fieldValue(privateMessage, "sender") == "peter" &&
		fieldValue(privateMessage, "display") == "peter" &&
		fieldValue(privateMessage, "text") == "dogs are cute",
		"NMDC private-message fields are decoded structurally");
	const auto mismatchedPrivateMessage = analyze("NMDC",
		"$To: john From: peter $<mallory> suspicious|");
	expect(mismatchedPrivateMessage.status == Status::Warning,
		"NMDC private messages warn when sender display names disagree");
	const auto mainChatPrivate = analyze("NMDC",
		"$MCTo: john $peter Cats are cute|");
	expect(mainChatPrivate.command == "$MCTo:" &&
		mainChatPrivate.name == "Main-chat-style private message" &&
		fieldValue(mainChatPrivate, "target") == "john" &&
		fieldValue(mainChatPrivate, "sender") == "peter" &&
		fieldValue(mainChatPrivate, "text") == "Cats are cute",
		"NMDC MCTo is decoded as a single-target main-chat-style message");
	const auto colonlessPrivate = analyze("NMDC",
		"$To john From: peter $<peter> invalid form|");
	expect(!colonlessPrivate.known,
		"NMDC private-message commands require their trailing colon");

	const std::string srSeparator(1, '\x05');
	const auto fileResult = analyze("NMDC",
		"$SR User1 ponies.txt" + srSeparator + "437 3/4" + srSeparator +
		"TTH:" + shortTth + " (192.0.2.1:411)" + srSeparator + "User2|");
	expect(fieldValue(fileResult, "source") == "User1" &&
		fieldValue(fileResult, "result") == "ponies.txt" &&
		fieldValue(fileResult, "size") == "437" &&
		fieldValue(fileResult, "free") == "3" &&
		fieldValue(fileResult, "total") == "4" &&
		fieldValue(fileResult, "TTH") == shortTth &&
		fieldValue(fileResult, "target") == "User2",
		"NMDC file search results expose source, size, slots, TTH, and target");
	const auto directoryResult = analyze("NMDC",
		"$SR User5 images 0/4" + srSeparator +
		"Testhub (192.0.2.1:411)|");
	expect(hasFieldName(directoryResult, "result", "Directory name") &&
		fieldValue(directoryResult, "result") == "images" &&
		fieldValue(directoryResult, "free") == "0" &&
		fieldValue(directoryResult, "hub") == "Testhub",
		"NMDC directory search results decode their distinct field layout");
	const auto invalidNumericResult = analyze("NMDC",
		"$SR User1 ponies.txt" + srSeparator + "not-a-size 5/4" +
		srSeparator + "Testhub (:70000)|");
	expect(invalidNumericResult.status == Status::Invalid,
		"NMDC search results validate size, slots, host, and port metadata");
	const auto missingEndpointResult = analyze("NMDC",
		"$SR User5 images 0/4" + srSeparator + "Testhub|");
	expect(missingEndpointResult.status == Status::Invalid,
		"NMDC search results require their hub endpoint");
	const auto emptyPassiveTargetResult = analyze("NMDC",
		"$SR User5 images 0/4" + srSeparator +
		"Testhub (192.0.2.1:411)" + srSeparator + "|");
	expect(emptyPassiveTargetResult.status == Status::Invalid,
		"NMDC search results reject an explicit empty passive target");

	const auto classicCtm = analyze("NMDC",
		"$ConnectToMe john 192.0.2.1:412S|");
	expect(fieldValue(classicCtm, "remote") == "john" &&
		fieldValue(classicCtm, "endpoint") == "192.0.2.1:412" &&
		fieldValue(classicCtm, "TLS") == "Requested",
		"NMDC classic ConnectToMe and TLS suffix are decoded");
	const auto modernCtm = analyze("NMDC",
		"$ConnectToMe peter john 192.0.2.1:412|");
	expect(fieldValue(modernCtm, "sender") == "peter" &&
		fieldValue(modernCtm, "remote") == "john",
		"NMDC modern ConnectToMe distinguishes sender and remote nickname");
	const auto natCtm = analyze("NMDC",
		"$ConnectToMe Client1 192.0.2.1:412NS Client2|");
	expect(fieldValue(natCtm, "remote") == "Client1" &&
		fieldValue(natCtm, "peer") == "Client2" &&
		fieldValue(natCtm, "NAT") == "Initiator" &&
		fieldValue(natCtm, "TLS") == "Requested",
		"NMDC NAT ConnectToMe suffixes and peer nickname are decoded");
	const auto natResponderCtm = analyze("NMDC",
		"$ConnectToMe Client2 192.0.2.2:412R|");
	expect(natResponderCtm.status == Status::Valid &&
		fieldValue(natResponderCtm, "NAT") == "Responder",
		"NMDC NAT responder R suffix is decoded");
	const auto secureNatResponderCtm = analyze("NMDC",
		"$ConnectToMe Client2 192.0.2.2:412RS|");
	expect(secureNatResponderCtm.status == Status::Valid &&
		fieldValue(secureNatResponderCtm, "NAT") == "Responder" &&
		fieldValue(secureNatResponderCtm, "TLS") == "Requested",
		"NMDC combined NAT responder and TLS suffixes are decoded");
	const auto nonCanonicalNatInitiator = analyze("NMDC",
		"$ConnectToMe Client1 192.0.2.1:412SN Client2|");
	const auto nonCanonicalNatResponder = analyze("NMDC",
		"$ConnectToMe Client2 192.0.2.2:412SR|");
	expect(nonCanonicalNatInitiator.status == Status::Invalid &&
		nonCanonicalNatResponder.status == Status::Invalid,
		"NMDC ConnectToMe requires canonical NS/RS suffix ordering");
	const auto emptyHostCtm = analyze("NMDC", "$ConnectToMe john :412|");
	const auto nonNumericPortCtm = analyze("NMDC",
		"$ConnectToMe john example.invalid:notaport|");
	const auto outOfRangePortCtm = analyze("NMDC",
		"$ConnectToMe john example.invalid:65536|");
	expect(emptyHostCtm.status == Status::Invalid &&
		nonNumericPortCtm.status == Status::Invalid &&
		outOfRangePortCtm.status == Status::Invalid,
		"NMDC ConnectToMe rejects empty hosts and invalid ports");
	const auto reverseCtm = analyze("NMDC",
		"$RevConnectToMe peter john|");
	expect(fieldValue(reverseCtm, "sender") == "peter" &&
		fieldValue(reverseCtm, "remote") == "john",
		"NMDC reverse connection request distinguishes both nicknames");
	const auto advancedCtmRequest = analyze("NMDC",
		"$CTM john$412$00AF|");
	expect(advancedCtmRequest.status == Status::Valid &&
		fieldValue(advancedCtmRequest, "peer") == "john" &&
		fieldValue(advancedCtmRequest, "port") == "412" &&
		fieldValue(advancedCtmRequest, "id") == "00AF",
		"NMDC ACTM request decodes peer, port, and connection ID");
	const auto advancedCtmForward = analyze("NMDC",
		"$CTM 192.0.2.10$1511$00B0|");
	expect(advancedCtmForward.status == Status::Valid &&
		fieldValue(advancedCtmForward, "peer") == "192.0.2.10",
		"NMDC ACTM forwarded request accepts a sender address");
	const auto advancedCtmHandshake = analyze("NMDC", "$CTM A91E|");
	expect(advancedCtmHandshake.status == Status::Valid &&
		fieldValue(advancedCtmHandshake, "id") == "A91E",
		"NMDC ACTM client handshake decodes its four-digit ID");
	const auto advancedReverseCtm = analyze("NMDC", "$RCTM john|");
	expect(advancedReverseCtm.status == Status::Valid &&
		fieldValue(advancedReverseCtm, "remote") == "john",
		"NMDC ACTM reverse request decodes its remote nickname");
	const auto invalidAdvancedCtm = analyze("NMDC",
		"$CTM john$70000$XYZ|");
	expect(invalidAdvancedCtm.status == Status::Invalid,
		"NMDC ACTM validates its port and four-digit hexadecimal ID");

	const auto lock = analyze("NMDC",
		"$Lock EXTENDEDPROTOCOLABC Pk=DCPLUSPLUS0.882Ref=example.com:411|");
	expect(hasFieldName(lock, "Pk", "Legacy implementation identifier"),
		"NMDC Lock Pk is not mislabeled as a cryptographic key");
	const auto version = analyze("NMDC", "$Version 1,0091|");
	expect(version.name == "Legacy client version marker",
		"NMDC Version is classified as a legacy client marker");

	const auto incrementalInfo = analyze("NMDC",
		"$IN john$DNew description$S1024$Ts3 v0.882|");
	expect(fieldValue(incrementalInfo, "nick") == "john" &&
		hasFieldName(incrementalInfo, "D", "Description") &&
		hasFieldName(incrementalInfo, "S", "Share size") &&
		hasFieldName(incrementalInfo, "T.s", "Tag upload slots") &&
		hasFieldName(incrementalInfo, "T.v", "Tag version"),
		"NMDC incremental user information identifiers are decoded");
	const auto hubInfo = analyze("NMDC",
		"$HubINFO Test Hub$hub.example:411$Description$500$1024$2$5$"
		"Public$owner@example.invalid$Public$UTF-8|");
	expect(fieldValue(hubInfo, "name") == "Test Hub" &&
		fieldValue(hubInfo, "address") == "hub.example:411" &&
		fieldValue(hubInfo, "category") == "Public" &&
		fieldValue(hubInfo, "encoding") == "UTF-8",
		"NMDC HubINFO positional fields are decoded");

	const auto compressed = analyze("NMDC",
		std::string("$ZOn ") + "opaque-secret-compressed-data|");
	expect(compressed.sensitive &&
		!containsSecret(compressed, "opaque-secret-compressed-data"),
		"opaque compressed NMDC payload is not exposed or decompressed");
	const auto streamedCompressed = analyze("NMDC",
		std::string("$ZOn|") + "opaque-stream-secret");
	expect(streamedCompressed.sensitive &&
		!containsSecret(streamedCompressed, "opaque-stream-secret"),
		"NMDC ZPipe stream bytes after ZOn are redacted without decompression");

	const auto vendorPassword = analyze("NMDC", "$VendorAuth swordfish|");
	expect(!vendorPassword.known && vendorPassword.sensitive &&
		!containsSecret(vendorPassword, "swordfish"),
		"credential-like vendor commands are conservatively redacted");

	const auto unknownNmdc = analyze("NMDC", "$VendorFeature alpha beta|");
	expect(!unknownNmdc.known && unknownNmdc.status == Status::Warning &&
		unknownNmdc.safeMessage.find("alpha beta") != std::string::npos,
		"non-sensitive vendor NMDC commands remain inspectable");

	const std::string utf8Name = "Jos\xC3\xA9";
	const auto validUtf8 = analyze("ADC", "IINF NI" + utf8Name);
	expect(fieldValue(validUtf8, "NI") == utf8Name &&
		validUtf8.safeMessage.find(utf8Name) != std::string::npos &&
		isValidUtf8(protocol_analyzer::formatDetails(validUtf8)),
		"valid UTF-8 text is preserved through analyzer sanitization");
	std::string invalidUtf8 = "IINF NIbad";
	invalidUtf8.push_back(static_cast<char>(0xc3));
	invalidUtf8.push_back('(');
	invalidUtf8.push_back(static_cast<char>(0xff));
	const auto escapedInvalidUtf8 = analyze("ADC", invalidUtf8);
	const auto escapedInvalidDetails =
		protocol_analyzer::formatDetails(escapedInvalidUtf8);
	expect(escapedInvalidUtf8.safeMessage.find("\\xC3(\\xFF") !=
			std::string::npos &&
		fieldValue(escapedInvalidUtf8, "NI").find("\\xC3(\\xFF") !=
			std::string::npos &&
		isValidUtf8(escapedInvalidUtf8.safeMessage) &&
		isValidUtf8(escapedInvalidDetails),
		"invalid UTF-8 bytes are hex-escaped before reaching inspector text");
	std::string rawBinary;
	rawBinary.push_back(static_cast<char>(0x0b));
	rawBinary.push_back(static_cast<char>(0x19));
	rawBinary.push_back(static_cast<char>(0xff));
	rawBinary.push_back('X');
	rawBinary.push_back(static_cast<char>(0x0c));
	const auto uncorrelatedBinary = analyze("ADC", rawBinary);
	expect(uncorrelatedBinary.safeMessage == "\\x0B\\x19\\xFFX\\x0C" &&
		isValidUtf8(uncorrelatedBinary.safeMessage) &&
		isValidUtf8(protocol_analyzer::formatDetails(uncorrelatedBinary)),
		"uncorrelated raw binary is display-safe when BLOM state is unavailable");
	protocol_analyzer::Result boundaryUtf8;
	boundaryUtf8.family = "ADC";
	boundaryUtf8.command = "BLOM-DATA";
	boundaryUtf8.action = boundaryUtf8.command;
	boundaryUtf8.name = "Boundary test";
	boundaryUtf8.category = "Transfer";
	boundaryUtf8.routing = "Binary";
	for(size_t i = 0; i < 40000; ++i) {
		boundaryUtf8.safeMessage += "\xC3\xA9";
	}
	expect(isValidUtf8(protocol_analyzer::formatDetails(boundaryUtf8)),
		"bounded inspector output never truncates inside a UTF-8 sequence");

	std::string oversized(80 * 1024, 'A');
	oversized.replace(0, 4, "IINF");
	const auto bounded = analyze("ADC", oversized);
	expect(bounded.safeMessage.size() <= 64 * 1024 + 1024 &&
		bounded.status == Status::Invalid,
		"oversized analyzer input is bounded and marked invalid");
	expect(protocol_analyzer::formatDetails(bounded).size() <= 32 * 1024 + 64,
		"inspector rendering is bounded");

	std::mt19937_64 random(0xDCC0FFEEULL);
	const auto started = std::chrono::steady_clock::now();
	bool fuzzBoundsHeld = true;
	for(size_t iteration = 0; iteration < 20000; ++iteration) {
		const size_t length = static_cast<size_t>(random() % 2048);
		std::string fuzz(length, '\0');
		for(char& ch : fuzz) {
			ch = static_cast<char>(random() & 0xffU);
		}
		const auto fuzzed = analyze((iteration & 1U) ? "ADC" : "NMDC", fuzz);
		fuzzBoundsHeld = fuzzBoundsHeld && fuzzed.fields.size() <= 64 &&
			fuzzed.warnings.size() <= 16 &&
			fuzzed.safeMessage.size() <= 64 * 1024 + 1024;
		if(!fuzzBoundsHeld) {
			break;
		}
	}
	expect(fuzzBoundsHeld, "adversarial input respects parser allocation limits");
	const auto elapsed = std::chrono::steady_clock::now() - started;
	expect(elapsed < std::chrono::seconds(10),
		"adversarial parser test completes within the performance budget");

	if(failures) {
		std::cerr << failures << " protocol-analyzer assertion(s) failed\n";
		return 1;
	}
	std::cout << "All protocol analyzer checks passed\n";
	return 0;
}
