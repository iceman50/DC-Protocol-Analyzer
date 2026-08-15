/*
* Copyright (C) 2022-2026 iceman50
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include "stdafx.h"
#include "CustomTitleBar.h"
#include "SettingsDlg.h"
#include "GUI.h"
#include "UIStyles.h"

#include <pluginsdk/Config.h>
#include <pluginsdk/Util.h>

#include <dwt/widgets/Button.h>
#include <dwt/widgets/CheckBox.h>
#include <dwt/widgets/ColorDialog.h>
#include <dwt/widgets/ComboBox.h>
#include <dwt/widgets/Grid.h>
#include <dwt/widgets/GroupBox.h>
#include <dwt/widgets/Label.h>
#include <dwt/widgets/SaveDialog.h>
#include <dwt/widgets/TextBox.h>

#include <limits>

// dwt defines another tstring...
typedef tstring _tstring;
#define tstring _tstring

using dcapi::Config;
using dcapi::Util;

using namespace dwt;

namespace Palette = protocol_analyzer::ui::Palette;

namespace {

bool parseUnsignedText(const tstring& input, uint64_t& parsed) noexcept {
	if(input.empty()) {
		return false;
	}
	uint64_t result = 0;
	for(const auto ch : input) {
		if(ch < _T('0') || ch > _T('9')) {
			return false;
		}
		const auto digit = static_cast<uint64_t>(ch - _T('0'));
		if(result > ((std::numeric_limits<uint64_t>::max)() - digit) / 10) {
			return false;
		}
		result = result * 10 + digit;
	}
	parsed = result;
	return true;
}

}

SettingsDlg::SettingsDlg(dwt::Widget* parent, GUI& owner_) :
	BaseType(parent),
	owner(owner_),
	customTitleBar(nullptr),
	grid(nullptr),
	paletteTheme(nullptr),
	paletteRole(nullptr),
	paletteColor(nullptr),
	paletteHint(nullptr),
	captureQueueBox(nullptr),
	captureQueueMemoryBox(nullptr),
	clipboardLimitBox(nullptr),
	resourceLimitHint(nullptr),
	editingDarkPalette(protocol_analyzer::ui::isDarkMode()),
	selectedColorRole(Palette::Role::Background)
{
	onInitDialog([this] { return handleInitDialog(); });
}

SettingsDlg::~SettingsDlg() {
}

int SettingsDlg::run() {
	create(Seed(dwt::Point(760, 760)));
	return show();
}

bool SettingsDlg::handleInitDialog() {
	const auto uiFont = protocol_analyzer::ui::makeFont(getDpi(), 9);
	const auto titleFont = protocol_analyzer::ui::makeFont(getDpi(), 18, FW_SEMIBOLD);
	const auto sectionFont = protocol_analyzer::ui::makeFont(getDpi(), 9, FW_SEMIBOLD);

	setFont(uiFont);
	protocol_analyzer::ui::styleSurface(this);
	customTitleBar.reset(new protocol_analyzer::ui::CustomTitleBar(this, uiFont));

	grid = addChild(Grid::Seed(6, 1));
	grid->column(0).mode = GridInfo::FILL;
	grid->setSpacing(12);
	grid->setFont(uiFont);
	protocol_analyzer::ui::styleSurface(grid);

	{
		auto header = grid->addChild(Grid::Seed(2, 1));
		header->column(0).mode = GridInfo::FILL;
		header->row(0).mode = GridInfo::AUTO;
		header->row(1).mode = GridInfo::AUTO;
		header->setSpacing(4);
		protocol_analyzer::ui::styleSurface(header);

		Label::Seed titleSeed(_T("Preferences"));
		titleSeed.font = titleFont;
		auto title = header->addChild(titleSeed);
		title->setFont(titleFont);
		title->setColor(protocol_analyzer::ui::palette().text, protocol_analyzer::ui::palette().window);

		Label::Seed subtitleSeed(
			_T("Tune capture capacity, clipboard safety, appearance, timestamps, redaction, and logging."));
		subtitleSeed.font = uiFont;
		auto subtitle = header->addChild(subtitleSeed);
		subtitle->setFont(uiFont);
		subtitle->setColor(protocol_analyzer::ui::palette().muted, protocol_analyzer::ui::palette().window);
	}

	{
		GroupBox::Seed paletteSeed(_T("Display color palette"));
		paletteSeed.font = sectionFont;
		auto paletteGroup = grid->addChild(paletteSeed);
		protocol_analyzer::ui::styleGroupBox(paletteGroup);
		auto content = paletteGroup->addChild(Grid::Seed(3, 4));
		content->column(0).size = 112;
		content->column(1).mode = GridInfo::FILL;
		content->column(2).size = 112;
		content->column(3).mode = GridInfo::FILL;
		content->setSpacing(8);
		protocol_analyzer::ui::styleSurface(content);

		Label::Seed themeLabelSeed(_T("Palette"));
		themeLabelSeed.font = uiFont;
		auto themeLabel = content->addChild(themeLabelSeed);
		themeLabel->setFont(uiFont);
		themeLabel->setColor(protocol_analyzer::ui::palette().muted, protocol_analyzer::ui::palette().window);

		ComboBox::Seed themeSeed;
		themeSeed.style |= CBS_DROPDOWNLIST;
		themeSeed.font = uiFont;
		paletteTheme = content->addChild(themeSeed);
		paletteTheme->setAccessibleName(_T("Palette theme"));
		paletteTheme->addValue(_T("Light"));
		paletteTheme->addValue(_T("Dark"));
		paletteTheme->setSelected(editingDarkPalette ? 1 : 0);
		protocol_analyzer::ui::styleComboBox(paletteTheme);

		Label::Seed roleLabelSeed(_T("Display element"));
		roleLabelSeed.font = uiFont;
		auto roleLabel = content->addChild(roleLabelSeed);
		roleLabel->setFont(uiFont);
		roleLabel->setColor(protocol_analyzer::ui::palette().muted, protocol_analyzer::ui::palette().window);

		ComboBox::Seed roleSeed;
		roleSeed.style |= CBS_DROPDOWNLIST;
		roleSeed.font = uiFont;
		paletteRole = content->addChild(roleSeed);
		paletteRole->setAccessibleName(_T("Display element color"));
		for(const auto& role : Palette::roles()) {
			paletteRole->addValue(role.label);
		}
		paletteRole->setSelected(static_cast<int>(selectedColorRole));
		protocol_analyzer::ui::styleComboBox(paletteRole);

		Label::Seed colorLabelSeed(_T("Current color"));
		colorLabelSeed.font = uiFont;
		auto colorLabel = content->addChild(colorLabelSeed);
		content->setWidget(colorLabel, 1, 0);
		colorLabel->setFont(uiFont);
		colorLabel->setColor(protocol_analyzer::ui::palette().muted, protocol_analyzer::ui::palette().window);

		Button::Seed colorSeed(_T("Change color\u2026"));
		colorSeed.font = uiFont;
		colorSeed.padding = Point(14, 5);
		paletteColor = content->addChild(colorSeed);
		content->setWidget(paletteColor, 1, 1);
		paletteColor->setAccessibleName(_T("Change selected display color"));
		paletteColor->onClicked([this] { choosePaletteColor(); });
		protocol_analyzer::ui::styleColorButton(paletteColor, [this] {
			return Palette::get(selectedColorRole, editingDarkPalette);
		});

		Button::Seed resetColorSeed(_T("Reset color"));
		resetColorSeed.font = uiFont;
		resetColorSeed.padding = Point(14, 5);
		auto resetColorButton = content->addChild(resetColorSeed);
		content->setWidget(resetColorButton, 1, 2);
		resetColorButton->onClicked([this] { resetPaletteColor(); });
		protocol_analyzer::ui::styleButton(resetColorButton);

		Button::Seed resetPaletteSeed(_T("Reset palette"));
		resetPaletteSeed.font = uiFont;
		resetPaletteSeed.padding = Point(14, 5);
		auto resetPaletteButton = content->addChild(resetPaletteSeed);
		content->setWidget(resetPaletteButton, 1, 3);
		resetPaletteButton->onClicked([this] { resetPalette(); });
		protocol_analyzer::ui::styleButton(resetPaletteButton);

		Label::Seed hintSeed;
		hintSeed.font = uiFont;
		paletteHint = content->addChild(hintSeed);
		content->setWidget(paletteHint, 2, 0, 1, 4);
		paletteHint->setFont(uiFont);
		paletteHint->setColor(protocol_analyzer::ui::palette().muted, protocol_analyzer::ui::palette().window);

		paletteTheme->onSelectionChanged([this] {
			editingDarkPalette = paletteTheme->getSelected() == 1;
			refreshPaletteEditor();
		});
		paletteRole->onSelectionChanged([this] {
			const int selected = paletteRole->getSelected();
			if(selected >= 0 && selected < static_cast<int>(Palette::Role::Count)) {
				selectedColorRole = static_cast<Palette::Role>(selected);
				refreshPaletteEditor();
			}
		});
	}

	{
		GroupBox::Seed formattingSeed(_T("Message formatting"));
		formattingSeed.font = sectionFont;
		auto formatting = grid->addChild(formattingSeed);
		protocol_analyzer::ui::styleGroupBox(formatting);
		auto content = formatting->addChild(Grid::Seed(3, 2));
		content->column(0).size = 112;
		content->column(1).mode = GridInfo::FILL;
		content->setSpacing(8);
		protocol_analyzer::ui::styleSurface(content);

		Label::Seed timestampLabelSeed(_T("Timestamp"));
		timestampLabelSeed.font = uiFont;
		auto timestampLabel = content->addChild(timestampLabelSeed);
		timestampLabel->setFont(uiFont);
		timestampLabel->setColor(protocol_analyzer::ui::palette().muted, protocol_analyzer::ui::palette().window);

		timestamp = Config::getConfig("TimeStampFormat");
		TextBox::Seed timestampSeed(Util::toT(timestamp));
		timestampSeed.style |= ES_AUTOHSCROLL;
		timestampSeed.font = uiFont;
		auto timestampBox = content->addChild(timestampSeed);
		timestampBox->setTextLimit(64);
		timestampBox->setCue(_T("strftime pattern, for example [%Y-%m-%d %H:%M:%S]"));
		timestampBox->setAccessibleName(_T("Timestamp format"));
		timestampBox->setColor(protocol_analyzer::ui::palette().text, protocol_analyzer::ui::palette().panel);
		timestampBox->onUpdated([this, timestampBox] {
			timestamp = Util::fromT(timestampBox->getText().substr(0, 64));
			Config::setConfig("TimeStampFormat", timestamp);
		});

		CheckBox::Seed redactionSeed(
			_T("Show sensitive values (disable redaction)"));
		redactionSeed.font = uiFont;
		auto redaction = content->addChild(redactionSeed);
		content->setWidget(redaction, 1, 0, 1, 2);
		redaction->setChecked(Config::getBoolConfig("DisableRedaction"));
		redaction->setAccessibleName(
			_T("Show sensitive protocol values and disable redaction"));
		redaction->setAccessibleHelpText(
			_T("When enabled, newly captured credentials and private identifiers ")
			_T("are shown and may be written to the protocol log."));
		protocol_analyzer::ui::styleCheckBox(redaction);
		redaction->onClicked([redaction] {
			Config::setConfig("DisableRedaction", redaction->getChecked());
		});

		Label::Seed redactionHintSeed(
			_T("Applies to newly captured rows and file logs; existing history is unchanged."));
		redactionHintSeed.font = uiFont;
		auto redactionHint = content->addChild(redactionHintSeed);
		content->setWidget(redactionHint, 2, 0, 1, 2);
		redactionHint->setFont(uiFont);
		redactionHint->setColor(protocol_analyzer::ui::palette().danger, protocol_analyzer::ui::palette().window);
	}

	{
		GroupBox::Seed queueSeed(_T("Resource limits"));
		queueSeed.font = sectionFont;
		auto queueGroup = grid->addChild(queueSeed);
		protocol_analyzer::ui::styleGroupBox(queueGroup);
		auto content = queueGroup->addChild(Grid::Seed(4, 3));
		content->column(0).size = 112;
		content->column(1).mode = GridInfo::FILL;
		content->column(2).mode = GridInfo::AUTO;
		content->setSpacing(8);
		protocol_analyzer::ui::styleSurface(content);

		Label::Seed capacityLabelSeed(_T("Pending messages"));
		capacityLabelSeed.font = uiFont;
		auto capacityLabel = content->addChild(capacityLabelSeed);
		content->setWidget(capacityLabel, 0, 0);
		capacityLabel->setFont(uiFont);
		capacityLabel->setColor(protocol_analyzer::ui::palette().muted, protocol_analyzer::ui::palette().window);

		const auto capacity = GUI::normalizeCaptureQueueCapacity(
			Config::getIntConfig("CaptureQueueCapacity"));
		TextBox::Seed capacitySeed(Util::toT(std::to_string(capacity)));
		capacitySeed.style |= ES_AUTOHSCROLL | ES_NUMBER;
		capacitySeed.font = uiFont;
		captureQueueBox = content->addChild(capacitySeed);
		content->setWidget(captureQueueBox, 0, 1);
		captureQueueBox->setTextLimit(10);
		captureQueueBox->setCue(_T("64 to 65536"));
		captureQueueBox->setAccessibleName(_T("Capture queue message capacity"));
		captureQueueBox->setColor(protocol_analyzer::ui::palette().text, protocol_analyzer::ui::palette().panel);

		Button::Seed applySeed(_T("Apply"));
		applySeed.font = uiFont;
		applySeed.padding = Point(14, 5);
		auto applyButton = content->addChild(applySeed);
		content->setWidget(applyButton, 0, 2);
		applyButton->onClicked([this] { applyCaptureQueueCapacity(); });
		protocol_analyzer::ui::styleButton(applyButton);

		Label::Seed queueMemoryLabelSeed(_T("Queue memory (MiB)"));
		queueMemoryLabelSeed.font = uiFont;
		auto queueMemoryLabel = content->addChild(queueMemoryLabelSeed);
		content->setWidget(queueMemoryLabel, 1, 0);
		queueMemoryLabel->setFont(uiFont);
		queueMemoryLabel->setColor(protocol_analyzer::ui::palette().muted,
			protocol_analyzer::ui::palette().window);

		const auto queueMemoryLimit = GUI::getCaptureQueueMemoryLimitMiB();
		TextBox::Seed queueMemorySeed(
			Util::toT(std::to_string(queueMemoryLimit)));
		queueMemorySeed.style |= ES_AUTOHSCROLL | ES_NUMBER;
		queueMemorySeed.font = uiFont;
		captureQueueMemoryBox = content->addChild(queueMemorySeed);
		content->setWidget(captureQueueMemoryBox, 1, 1);
		captureQueueMemoryBox->setTextLimit(10);
		captureQueueMemoryBox->setCue(_T("1 to 64"));
		captureQueueMemoryBox->setAccessibleName(
			_T("Pending capture queue memory limit in MiB"));
		captureQueueMemoryBox->setAccessibleHelpText(
			_T("Bounds messages waiting for processing by the UI timer."));
		captureQueueMemoryBox->setColor(protocol_analyzer::ui::palette().text,
			protocol_analyzer::ui::palette().panel);

		Button::Seed applyQueueMemorySeed(_T("Apply"));
		applyQueueMemorySeed.font = uiFont;
		applyQueueMemorySeed.padding = Point(14, 5);
		auto applyQueueMemoryButton = content->addChild(applyQueueMemorySeed);
		content->setWidget(applyQueueMemoryButton, 1, 2);
		applyQueueMemoryButton->onClicked(
			[this] { applyCaptureQueueMemoryLimit(); });
		protocol_analyzer::ui::styleButton(applyQueueMemoryButton);

		Label::Seed clipboardLabelSeed(_T("Clipboard (MiB)"));
		clipboardLabelSeed.font = uiFont;
		auto clipboardLabel = content->addChild(clipboardLabelSeed);
		content->setWidget(clipboardLabel, 2, 0);
		clipboardLabel->setFont(uiFont);
		clipboardLabel->setColor(protocol_analyzer::ui::palette().muted,
			protocol_analyzer::ui::palette().window);

		const auto clipboardLimit = GUI::getClipboardLimitMiB();
		TextBox::Seed clipboardSeed(
			Util::toT(std::to_string(clipboardLimit)));
		clipboardSeed.style |= ES_AUTOHSCROLL | ES_NUMBER;
		clipboardSeed.font = uiFont;
		clipboardLimitBox = content->addChild(clipboardSeed);
		content->setWidget(clipboardLimitBox, 2, 1);
		clipboardLimitBox->setTextLimit(10);
		clipboardLimitBox->setCue(_T("1 to 64"));
		clipboardLimitBox->setAccessibleName(
			_T("Clipboard output safety limit in MiB"));
		clipboardLimitBox->setAccessibleHelpText(
			_T("Limits temporary text assembly and the Windows clipboard allocation."));
		clipboardLimitBox->setColor(protocol_analyzer::ui::palette().text,
			protocol_analyzer::ui::palette().panel);

		Button::Seed applyClipboardSeed(_T("Apply"));
		applyClipboardSeed.font = uiFont;
		applyClipboardSeed.padding = Point(14, 5);
		auto applyClipboardButton = content->addChild(applyClipboardSeed);
		content->setWidget(applyClipboardButton, 2, 2);
		applyClipboardButton->onClicked([this] { applyClipboardLimit(); });
		protocol_analyzer::ui::styleButton(applyClipboardButton);

		Label::Seed resourceHintSeed(
			_T("Messages: 64\u201365,536. Memory limits: 1\u201364 MiB; defaults are 4 MiB."));
		resourceHintSeed.font = uiFont;
		resourceLimitHint = content->addChild(resourceHintSeed);
		content->setWidget(resourceLimitHint, 3, 0, 1, 3);
		resourceLimitHint->setFont(uiFont);
		resourceLimitHint->setColor(protocol_analyzer::ui::palette().muted,
			protocol_analyzer::ui::palette().window);
	}

	{
		GroupBox::Seed loggingSeed(_T("File logging"));
		loggingSeed.font = sectionFont;
		auto logging = grid->addChild(loggingSeed);
		protocol_analyzer::ui::styleGroupBox(logging);
		auto content = logging->addChild(Grid::Seed(2, 3));
		content->column(0).size = 112;
		content->column(1).mode = GridInfo::FILL;
		content->column(2).mode = GridInfo::AUTO;
		content->setSpacing(8);
		protocol_analyzer::ui::styleSurface(content);

		Label::Seed pathLabelSeed(_T("Log file"));
		pathLabelSeed.font = uiFont;
		auto pathLabel = content->addChild(pathLabelSeed);
		pathLabel->setFont(uiFont);
		pathLabel->setColor(protocol_analyzer::ui::palette().muted, protocol_analyzer::ui::palette().window);

		log = Config::getConfig("Log");
		TextBox::Seed pathSeed(Util::toT(log));
		pathSeed.style |= ES_AUTOHSCROLL;
		pathSeed.font = uiFont;
		auto pathBox = content->addChild(pathSeed);
		pathBox->setTextLimit(32767);
		pathBox->setCue(_T("Leave empty to disable file logging"));
		pathBox->setAccessibleName(_T("Protocol log file path"));
		pathBox->setColor(protocol_analyzer::ui::palette().text, protocol_analyzer::ui::palette().panel);
		pathBox->onUpdated([this, pathBox] {
			log = Util::fromT(pathBox->getText());
			Config::setConfig("Log", log);
		});

		Button::Seed browseSeed(_T("Browse\u2026"));
		browseSeed.font = uiFont;
		browseSeed.padding = Point(14, 5);
		auto browse = content->addChild(browseSeed);
		browse->onClicked([this, pathBox] {
			auto file = Util::toT(log);
			if(SaveDialog(this).open(file)) {
				log = Util::fromT(file);
				Config::setConfig("Log", log);
				pathBox->setText(file);
			}
		});
		protocol_analyzer::ui::styleButton(browse);

		Label::Seed hintSeed(
			_T("UTF-8 logs rotate at 10 MiB (three backups) and follow the ")
			_T("sensitive-value redaction setting above."));
		hintSeed.font = uiFont;
		auto hint = content->addChild(hintSeed);
		content->setWidget(hint, 1, 1, 1, 2);
		hint->setFont(uiFont);
		hint->setColor(protocol_analyzer::ui::palette().muted, protocol_analyzer::ui::palette().window);
	}

	{
		auto footer = grid->addChild(Grid::Seed(1, 2));
		footer->column(0).mode = GridInfo::FILL;
		footer->column(1).mode = GridInfo::AUTO;
		footer->setSpacing(8);
		protocol_analyzer::ui::styleSurface(footer);

		Label::Seed noteSeed(_T("Changes are saved and applied immediately."));
		noteSeed.font = uiFont;
		auto note = footer->addChild(noteSeed);
		note->setFont(uiFont);
		note->setColor(protocol_analyzer::ui::palette().muted, protocol_analyzer::ui::palette().window);

		Button::Seed closeSeed(_T("Done"));
		closeSeed.style |= BS_DEFPUSHBUTTON;
		closeSeed.font = uiFont;
		closeSeed.padding = Point(20, 6);
		auto closeButton = footer->addChild(closeSeed);
		closeButton->onClicked([this] { ok(); });
		protocol_analyzer::ui::styleButton(closeButton, protocol_analyzer::ui::ButtonTone::Primary);
	}

	refreshPaletteEditor();
	setText(_T("Protocol Analyzer \u00b7 Preferences"));

	layout();
	onSized([this](const SizedEvent&) { layout(); });
	centerWindow();

	return false;
}

void SettingsDlg::ok() {
	if(!applyCaptureQueueCapacity()) {
		return;
	}
	if(!applyCaptureQueueMemoryLimit()) {
		return;
	}
	if(!applyClipboardLimit()) {
		return;
	}
	endDialog(IDOK);
}

bool SettingsDlg::applyCaptureQueueCapacity() {
	if(!captureQueueBox || !resourceLimitHint) {
		return false;
	}

	uint64_t parsed = 0;
	if(!parseUnsignedText(captureQueueBox->getText(), parsed)) {
		resourceLimitHint->setText(_T("Enter a whole number from 64 to 65,536 messages."));
		resourceLimitHint->setColor(protocol_analyzer::ui::palette().danger, protocol_analyzer::ui::palette().window);
		captureQueueBox->setFocus();
		return false;
	}

	const auto normalized = parsed > GUI::MAX_CAPTURE_QUEUE_CAPACITY ?
		GUI::MAX_CAPTURE_QUEUE_CAPACITY :
		GUI::normalizeCaptureQueueCapacity(static_cast<int64_t>(parsed));
	owner.setCaptureQueueCapacity(normalized);
	captureQueueBox->setText(Util::toT(std::to_string(normalized)));
	if(parsed != normalized) {
		resourceLimitHint->setText(
			_T("Message capacity adjusted to the supported range."));
	} else {
		resourceLimitHint->setText(
			_T("Message capacity applied immediately."));
	}
	resourceLimitHint->setColor(protocol_analyzer::ui::palette().muted, protocol_analyzer::ui::palette().window);
	return true;
}

bool SettingsDlg::applyCaptureQueueMemoryLimit() {
	if(!captureQueueMemoryBox || !resourceLimitHint) {
		return false;
	}

	uint64_t parsed = 0;
	if(!parseUnsignedText(captureQueueMemoryBox->getText(), parsed)) {
		resourceLimitHint->setText(
			_T("Enter a whole-number queue memory limit from 1 to 64 MiB."));
		resourceLimitHint->setColor(protocol_analyzer::ui::palette().danger,
			protocol_analyzer::ui::palette().window);
		captureQueueMemoryBox->setFocus();
		return false;
	}

	const auto normalized = parsed >
		static_cast<uint64_t>(GUI::MAX_CAPTURE_QUEUE_MEMORY_MIB) ?
		GUI::MAX_CAPTURE_QUEUE_MEMORY_MIB :
		GUI::normalizeCaptureQueueMemoryLimitMiB(
			static_cast<int64_t>(parsed));
	owner.setCaptureQueueMemoryLimitMiB(normalized);
	captureQueueMemoryBox->setText(Util::toT(std::to_string(normalized)));
	resourceLimitHint->setText(parsed == static_cast<uint64_t>(normalized) ?
		_T("Queue memory limit applied immediately.") :
		_T("Queue memory limit adjusted to the supported 1\u201364 MiB range."));
	resourceLimitHint->setColor(protocol_analyzer::ui::palette().muted,
		protocol_analyzer::ui::palette().window);
	return true;
}

bool SettingsDlg::applyClipboardLimit() {
	if(!clipboardLimitBox || !resourceLimitHint) {
		return false;
	}

	uint64_t parsed = 0;
	if(!parseUnsignedText(clipboardLimitBox->getText(), parsed)) {
		resourceLimitHint->setText(
			_T("Enter a whole number from 1 to 64 MiB."));
		resourceLimitHint->setColor(protocol_analyzer::ui::palette().danger,
			protocol_analyzer::ui::palette().window);
		clipboardLimitBox->setFocus();
		return false;
	}

	const auto normalized = parsed >
		static_cast<uint64_t>(GUI::MAX_CLIPBOARD_LIMIT_MIB) ?
		GUI::MAX_CLIPBOARD_LIMIT_MIB :
		GUI::normalizeClipboardLimitMiB(static_cast<int64_t>(parsed));
	GUI::setClipboardLimitMiB(normalized);
	clipboardLimitBox->setText(Util::toT(std::to_string(normalized)));
	resourceLimitHint->setText(parsed == static_cast<uint64_t>(normalized) ?
		_T("Applied immediately to whole-row and per-column copies.") :
		_T("Value adjusted to the supported 1\u201364 MiB range."));
	resourceLimitHint->setColor(protocol_analyzer::ui::palette().muted,
		protocol_analyzer::ui::palette().window);
	return true;
}

void SettingsDlg::layout() {
	auto size = getClientSize();
	const long titleBarHeight =
		customTitleBar ? customTitleBar->height() : 0;
	const long margin = scale(16);
	grid->resize(dwt::Rectangle(margin, titleBarHeight + margin,
		std::max(0L, size.x - margin * 2),
		std::max(0L, size.y - titleBarHeight - margin * 2)));
}

void SettingsDlg::refreshPaletteEditor() {
	if(!paletteColor || !paletteHint) {
		return;
	}

	const auto color = Palette::get(selectedColorRole, editingDarkPalette);
	TCHAR caption[64] {};
	_stprintf_s(caption, sizeof(caption) / sizeof(caption[0]),
		_T("#%02X%02X%02X  Change color\u2026"),
		GetRValue(color), GetGValue(color), GetBValue(color));
	paletteColor->setText(caption);
	paletteColor->redraw(true);

	tstring hint = editingDarkPalette ? _T("Editing the Dark display palette.") :
		_T("Editing the Light display palette.");
	hint += editingDarkPalette == protocol_analyzer::ui::isDarkMode() ?
		_T(" Changes are visible immediately.") :
		_T(" Changes appear when that mode is activated.");
	paletteHint->setText(hint);
}

void SettingsDlg::choosePaletteColor() {
	ColorDialog::ColorParams params(
		Palette::get(selectedColorRole, editingDarkPalette));
	if(ColorDialog(this).open(params)) {
		Palette::set(selectedColorRole, editingDarkPalette, params.getColor());
		if(editingDarkPalette == protocol_analyzer::ui::isDarkMode()) {
			GUI::refreshPalette();
		}
		refreshPaletteEditor();
	}
}

void SettingsDlg::resetPaletteColor() {
	Palette::set(selectedColorRole, editingDarkPalette,
		Palette::defaultColor(selectedColorRole, editingDarkPalette));
	if(editingDarkPalette == protocol_analyzer::ui::isDarkMode()) {
		GUI::refreshPalette();
	}
	refreshPaletteEditor();
}

void SettingsDlg::resetPalette() {
	Palette::reset(editingDarkPalette);
	if(editingDarkPalette == protocol_analyzer::ui::isDarkMode()) {
		GUI::refreshPalette();
	}
	refreshPaletteEditor();
}
