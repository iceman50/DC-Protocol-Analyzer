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

// dwt defines another tstring...
typedef tstring _tstring;
#define tstring _tstring

using dcapi::Config;
using dcapi::Util;

using namespace dwt;

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
	captureQueueHint(nullptr),
	editingDarkPalette(ui::isDarkMode()),
	selectedColorRole(table_colors::Role::Background)
{
	onInitDialog([this] { return handleInitDialog(); });
}

SettingsDlg::~SettingsDlg() {
}

int SettingsDlg::run() {
	create(Seed(dwt::Point(760, 700)));
	return show();
}

bool SettingsDlg::handleInitDialog() {
	const auto uiFont = ui::makeFont(getDpi(), 9);
	const auto titleFont = ui::makeFont(getDpi(), 18, FW_SEMIBOLD);
	const auto sectionFont = ui::makeFont(getDpi(), 9, FW_SEMIBOLD);

	setFont(uiFont);
	ui::styleSurface(this);
	customTitleBar.reset(new ui::CustomTitleBar(this, uiFont));

	grid = addChild(Grid::Seed(6, 1));
	grid->column(0).mode = GridInfo::FILL;
	grid->setSpacing(12);
	grid->setFont(uiFont);
	ui::styleSurface(grid);

	{
		auto header = grid->addChild(Grid::Seed(2, 1));
		header->column(0).mode = GridInfo::FILL;
		header->row(0).mode = GridInfo::AUTO;
		header->row(1).mode = GridInfo::AUTO;
		header->setSpacing(4);
		ui::styleSurface(header);

		Label::Seed titleSeed(_T("Preferences"));
		titleSeed.font = titleFont;
		auto title = header->addChild(titleSeed);
		title->setFont(titleFont);
		title->setColor(ui::palette().text, ui::palette().window);

		Label::Seed subtitleSeed(
			_T("Tune capture capacity, appearance, timestamps, redaction, and optional file logging."));
		subtitleSeed.font = uiFont;
		auto subtitle = header->addChild(subtitleSeed);
		subtitle->setFont(uiFont);
		subtitle->setColor(ui::palette().muted, ui::palette().window);
	}

	{
		GroupBox::Seed paletteSeed(_T("Display color palette"));
		paletteSeed.font = sectionFont;
		auto paletteGroup = grid->addChild(paletteSeed);
		ui::styleGroupBox(paletteGroup);
		auto content = paletteGroup->addChild(Grid::Seed(3, 4));
		content->column(0).size = 112;
		content->column(1).mode = GridInfo::FILL;
		content->column(2).size = 112;
		content->column(3).mode = GridInfo::FILL;
		content->setSpacing(8);
		ui::styleSurface(content);

		Label::Seed themeLabelSeed(_T("Palette"));
		themeLabelSeed.font = uiFont;
		auto themeLabel = content->addChild(themeLabelSeed);
		themeLabel->setFont(uiFont);
		themeLabel->setColor(ui::palette().muted, ui::palette().window);

		ComboBox::Seed themeSeed;
		themeSeed.style |= CBS_DROPDOWNLIST;
		themeSeed.font = uiFont;
		paletteTheme = content->addChild(themeSeed);
		paletteTheme->setAccessibleName(_T("Palette theme"));
		paletteTheme->addValue(_T("Light"));
		paletteTheme->addValue(_T("Dark"));
		paletteTheme->setSelected(editingDarkPalette ? 1 : 0);
		ui::styleComboBox(paletteTheme);

		Label::Seed roleLabelSeed(_T("Display element"));
		roleLabelSeed.font = uiFont;
		auto roleLabel = content->addChild(roleLabelSeed);
		roleLabel->setFont(uiFont);
		roleLabel->setColor(ui::palette().muted, ui::palette().window);

		ComboBox::Seed roleSeed;
		roleSeed.style |= CBS_DROPDOWNLIST;
		roleSeed.font = uiFont;
		paletteRole = content->addChild(roleSeed);
		paletteRole->setAccessibleName(_T("Display element color"));
		for(const auto& role : table_colors::roles()) {
			paletteRole->addValue(role.label);
		}
		paletteRole->setSelected(static_cast<int>(selectedColorRole));
		ui::styleComboBox(paletteRole);

		Label::Seed colorLabelSeed(_T("Current color"));
		colorLabelSeed.font = uiFont;
		auto colorLabel = content->addChild(colorLabelSeed);
		content->setWidget(colorLabel, 1, 0);
		colorLabel->setFont(uiFont);
		colorLabel->setColor(ui::palette().muted, ui::palette().window);

		Button::Seed colorSeed(_T("Change color\u2026"));
		colorSeed.font = uiFont;
		colorSeed.padding = Point(14, 5);
		paletteColor = content->addChild(colorSeed);
		content->setWidget(paletteColor, 1, 1);
		paletteColor->setAccessibleName(_T("Change selected display color"));
		paletteColor->onClicked([this] { choosePaletteColor(); });
		ui::styleColorButton(paletteColor, [this] {
			return table_colors::get(selectedColorRole, editingDarkPalette);
		});

		Button::Seed resetColorSeed(_T("Reset color"));
		resetColorSeed.font = uiFont;
		resetColorSeed.padding = Point(14, 5);
		auto resetColorButton = content->addChild(resetColorSeed);
		content->setWidget(resetColorButton, 1, 2);
		resetColorButton->onClicked([this] { resetPaletteColor(); });
		ui::styleButton(resetColorButton);

		Button::Seed resetPaletteSeed(_T("Reset palette"));
		resetPaletteSeed.font = uiFont;
		resetPaletteSeed.padding = Point(14, 5);
		auto resetPaletteButton = content->addChild(resetPaletteSeed);
		content->setWidget(resetPaletteButton, 1, 3);
		resetPaletteButton->onClicked([this] { resetPalette(); });
		ui::styleButton(resetPaletteButton);

		Label::Seed hintSeed;
		hintSeed.font = uiFont;
		paletteHint = content->addChild(hintSeed);
		content->setWidget(paletteHint, 2, 0, 1, 4);
		paletteHint->setFont(uiFont);
		paletteHint->setColor(ui::palette().muted, ui::palette().window);

		paletteTheme->onSelectionChanged([this] {
			editingDarkPalette = paletteTheme->getSelected() == 1;
			refreshPaletteEditor();
		});
		paletteRole->onSelectionChanged([this] {
			const int selected = paletteRole->getSelected();
			if(selected >= 0 && selected < static_cast<int>(table_colors::Role::Count)) {
				selectedColorRole = static_cast<table_colors::Role>(selected);
				refreshPaletteEditor();
			}
		});
	}

	{
		GroupBox::Seed formattingSeed(_T("Message formatting"));
		formattingSeed.font = sectionFont;
		auto formatting = grid->addChild(formattingSeed);
		ui::styleGroupBox(formatting);
		auto content = formatting->addChild(Grid::Seed(3, 2));
		content->column(0).size = 112;
		content->column(1).mode = GridInfo::FILL;
		content->setSpacing(8);
		ui::styleSurface(content);

		Label::Seed timestampLabelSeed(_T("Timestamp"));
		timestampLabelSeed.font = uiFont;
		auto timestampLabel = content->addChild(timestampLabelSeed);
		timestampLabel->setFont(uiFont);
		timestampLabel->setColor(ui::palette().muted, ui::palette().window);

		timestamp = Config::getConfig("TimeStampFormat");
		TextBox::Seed timestampSeed(Util::toT(timestamp));
		timestampSeed.style |= ES_AUTOHSCROLL;
		timestampSeed.font = uiFont;
		auto timestampBox = content->addChild(timestampSeed);
		timestampBox->setTextLimit(64);
		timestampBox->setCue(_T("strftime pattern, for example [%Y-%m-%d %H:%M:%S]"));
		timestampBox->setAccessibleName(_T("Timestamp format"));
		timestampBox->setColor(ui::palette().text, ui::palette().panel);
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
		ui::styleCheckBox(redaction);
		redaction->onClicked([redaction] {
			Config::setConfig("DisableRedaction", redaction->getChecked());
		});

		Label::Seed redactionHintSeed(
			_T("Applies to newly captured rows and file logs; existing history is unchanged."));
		redactionHintSeed.font = uiFont;
		auto redactionHint = content->addChild(redactionHintSeed);
		content->setWidget(redactionHint, 2, 0, 1, 2);
		redactionHint->setFont(uiFont);
		redactionHint->setColor(ui::palette().danger, ui::palette().window);
	}

	{
		GroupBox::Seed queueSeed(_T("Capture queue"));
		queueSeed.font = sectionFont;
		auto queueGroup = grid->addChild(queueSeed);
		ui::styleGroupBox(queueGroup);
		auto content = queueGroup->addChild(Grid::Seed(2, 3));
		content->column(0).size = 112;
		content->column(1).mode = GridInfo::FILL;
		content->column(2).mode = GridInfo::AUTO;
		content->setSpacing(8);
		ui::styleSurface(content);

		Label::Seed capacityLabelSeed(_T("Pending messages"));
		capacityLabelSeed.font = uiFont;
		auto capacityLabel = content->addChild(capacityLabelSeed);
		capacityLabel->setFont(uiFont);
		capacityLabel->setColor(ui::palette().muted, ui::palette().window);

		const auto capacity = GUI::normalizeCaptureQueueCapacity(
			Config::getIntConfig("CaptureQueueCapacity"));
		TextBox::Seed capacitySeed(Util::toT(std::to_string(capacity)));
		capacitySeed.style |= ES_AUTOHSCROLL | ES_NUMBER;
		capacitySeed.font = uiFont;
		captureQueueBox = content->addChild(capacitySeed);
		captureQueueBox->setTextLimit(10);
		captureQueueBox->setCue(_T("64 to 65536"));
		captureQueueBox->setAccessibleName(_T("Capture queue message capacity"));
		captureQueueBox->setColor(ui::palette().text, ui::palette().panel);

		Button::Seed applySeed(_T("Apply"));
		applySeed.font = uiFont;
		applySeed.padding = Point(14, 5);
		auto applyButton = content->addChild(applySeed);
		applyButton->onClicked([this] { applyCaptureQueueCapacity(); });
		ui::styleButton(applyButton);

		Label::Seed hintSeed(
			_T("Allowed range: 64\u201365,536 messages. The independent 4 MiB ")
			_T("memory ceiling always remains active."));
		hintSeed.font = uiFont;
		captureQueueHint = content->addChild(hintSeed);
		content->setWidget(captureQueueHint, 1, 1, 1, 2);
		captureQueueHint->setFont(uiFont);
		captureQueueHint->setColor(ui::palette().muted, ui::palette().window);
	}

	{
		GroupBox::Seed loggingSeed(_T("File logging"));
		loggingSeed.font = sectionFont;
		auto logging = grid->addChild(loggingSeed);
		ui::styleGroupBox(logging);
		auto content = logging->addChild(Grid::Seed(2, 3));
		content->column(0).size = 112;
		content->column(1).mode = GridInfo::FILL;
		content->column(2).mode = GridInfo::AUTO;
		content->setSpacing(8);
		ui::styleSurface(content);

		Label::Seed pathLabelSeed(_T("Log file"));
		pathLabelSeed.font = uiFont;
		auto pathLabel = content->addChild(pathLabelSeed);
		pathLabel->setFont(uiFont);
		pathLabel->setColor(ui::palette().muted, ui::palette().window);

		log = Config::getConfig("Log");
		TextBox::Seed pathSeed(Util::toT(log));
		pathSeed.style |= ES_AUTOHSCROLL;
		pathSeed.font = uiFont;
		auto pathBox = content->addChild(pathSeed);
		pathBox->setTextLimit(32767);
		pathBox->setCue(_T("Leave empty to disable file logging"));
		pathBox->setAccessibleName(_T("Protocol log file path"));
		pathBox->setColor(ui::palette().text, ui::palette().panel);
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
		ui::styleButton(browse);

		Label::Seed hintSeed(
			_T("UTF-8 logs rotate at 10 MiB (three backups) and follow the ")
			_T("sensitive-value redaction setting above."));
		hintSeed.font = uiFont;
		auto hint = content->addChild(hintSeed);
		content->setWidget(hint, 1, 1, 1, 2);
		hint->setFont(uiFont);
		hint->setColor(ui::palette().muted, ui::palette().window);
	}

	{
		auto footer = grid->addChild(Grid::Seed(1, 2));
		footer->column(0).mode = GridInfo::FILL;
		footer->column(1).mode = GridInfo::AUTO;
		footer->setSpacing(8);
		ui::styleSurface(footer);

		Label::Seed noteSeed(_T("Changes are saved and applied immediately."));
		noteSeed.font = uiFont;
		auto note = footer->addChild(noteSeed);
		note->setFont(uiFont);
		note->setColor(ui::palette().muted, ui::palette().window);

		Button::Seed closeSeed(_T("Done"));
		closeSeed.style |= BS_DEFPUSHBUTTON;
		closeSeed.font = uiFont;
		closeSeed.padding = Point(20, 6);
		auto closeButton = footer->addChild(closeSeed);
		closeButton->onClicked([this] { ok(); });
		ui::styleButton(closeButton, ui::ButtonTone::Primary);
	}

	refreshPaletteEditor();
	setText(_T("Protocol Analyzer \u00b7 Preferences"));

	layout();
	onSized([this](const SizedEvent&) { layout(); });
	centerWindow();

	return false;
}

void SettingsDlg::ok() {
	if(applyCaptureQueueCapacity()) {
		endDialog(IDOK);
	}
}

bool SettingsDlg::applyCaptureQueueCapacity() {
	if(!captureQueueBox || !captureQueueHint) {
		return false;
	}

	const auto input = captureQueueBox->getText();
	uint64_t parsed = 0;
	bool valid = !input.empty();
	for(const auto ch : input) {
		if(ch < _T('0') || ch > _T('9')) {
			valid = false;
			break;
		}
		parsed = parsed * 10 + static_cast<uint64_t>(ch - _T('0'));
	}
	if(!valid) {
		captureQueueHint->setText(_T("Enter a whole number from 64 to 65,536."));
		captureQueueHint->setColor(ui::palette().danger, ui::palette().window);
		captureQueueBox->setFocus();
		return false;
	}

	const auto normalized =
		GUI::normalizeCaptureQueueCapacity(static_cast<int64_t>(parsed));
	owner.setCaptureQueueCapacity(normalized);
	captureQueueBox->setText(Util::toT(std::to_string(normalized)));
	if(parsed != normalized) {
		captureQueueHint->setText(
			_T("Value adjusted to the supported range. The 4 MiB memory ceiling remains active."));
	} else {
		captureQueueHint->setText(
			_T("Applied immediately. The independent 4 MiB memory ceiling remains active."));
	}
	captureQueueHint->setColor(ui::palette().muted, ui::palette().window);
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

	const auto color = table_colors::get(selectedColorRole, editingDarkPalette);
	TCHAR caption[64] {};
	_stprintf_s(caption, sizeof(caption) / sizeof(caption[0]),
		_T("#%02X%02X%02X  Change color\u2026"),
		GetRValue(color), GetGValue(color), GetBValue(color));
	paletteColor->setText(caption);
	paletteColor->redraw(true);

	tstring hint = editingDarkPalette ? _T("Editing the Dark display palette.") :
		_T("Editing the Light display palette.");
	hint += editingDarkPalette == ui::isDarkMode() ?
		_T(" Changes are visible immediately.") :
		_T(" Changes appear when that mode is activated.");
	paletteHint->setText(hint);
}

void SettingsDlg::choosePaletteColor() {
	ColorDialog::ColorParams params(
		table_colors::get(selectedColorRole, editingDarkPalette));
	if(ColorDialog(this).open(params)) {
		table_colors::set(selectedColorRole, editingDarkPalette, params.getColor());
		if(editingDarkPalette == ui::isDarkMode()) {
			GUI::refreshTableColors();
		}
		refreshPaletteEditor();
	}
}

void SettingsDlg::resetPaletteColor() {
	table_colors::set(selectedColorRole, editingDarkPalette,
		table_colors::defaultColor(selectedColorRole, editingDarkPalette));
	if(editingDarkPalette == ui::isDarkMode()) {
		GUI::refreshTableColors();
	}
	refreshPaletteEditor();
}

void SettingsDlg::resetPalette() {
	table_colors::reset(editingDarkPalette);
	if(editingDarkPalette == ui::isDarkMode()) {
		GUI::refreshTableColors();
	}
	refreshPaletteEditor();
}
