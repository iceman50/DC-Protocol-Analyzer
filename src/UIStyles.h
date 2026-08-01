/*
* Copyright (C) 2026 iceman50
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

#ifndef PROTOCOL_ANALYZER_UI_STYLES_H
#define PROTOCOL_ANALYZER_UI_STYLES_H

#include <dwt/CanvasClasses.h>
#include <dwt/Rectangle.h>
#include <dwt/resources/Font.h>
#include <dwt/resources/Brush.h>
#include <dwt/resources/Pen.h>
#include <dwt/widgets/Button.h>
#include <dwt/widgets/CheckBox.h>
#include <dwt/widgets/ComboBox.h>
#include <dwt/widgets/GroupBox.h>
#include <dwt/widgets/TextBox.h>

#include <algorithm>
#include <functional>
#include <uxtheme.h>

namespace ui {

struct Palette {
	COLORREF window;
	COLORREF panel;
	COLORREF text;
	COLORREF muted;
	COLORREF accent;
	COLORREF accentHot;
	COLORREF accentPressed;
	COLORREF border;
	COLORREF rowAlternate;
	COLORREF success;
	COLORREF danger;
};

inline bool& darkModeState() {
	static bool enabled = false;
	return enabled;
}

inline void setDarkMode(bool enabled) {
	darkModeState() = enabled;
}

inline bool isDarkMode() {
	return darkModeState();
}

inline bool isHighContrast() {
	HIGHCONTRAST value { sizeof(HIGHCONTRAST) };
	return ::SystemParametersInfo(SPI_GETHIGHCONTRAST, sizeof(HIGHCONTRAST),
		&value, 0) &&
		(value.dwFlags & HCF_HIGHCONTRASTON) != 0;
}

class ScrollBarStyle final {
public:
	template<typename WidgetPointer>
	static void apply(WidgetPointer widget) {
		if(widget) {
			apply(widget->handle());
		}
	}

	static void apply(HWND window) {
		if(!window || !::IsWindow(window)) {
			return;
		}

		// Attached WS_HSCROLL/WS_VSCROLL bars are non-client elements, so let
		// Windows retain their native behavior while selecting its dark visual
		// style. Removing the override restores the system theme in light and
		// high-contrast modes.
		const auto dark = isDarkMode() && !isHighContrast();
		::SetWindowTheme(window, dark ? L"DarkMode_Explorer" : nullptr, nullptr);
		::RedrawWindow(window, nullptr, nullptr, RDW_INVALIDATE | RDW_FRAME);
	}
};

inline const Palette& palette() {
	static const Palette light {
		RGB(246, 248, 251),
		RGB(255, 255, 255),
		RGB(30, 41, 59),
		RGB(100, 116, 139),
		RGB(37, 99, 235),
		RGB(29, 78, 216),
		RGB(30, 64, 175),
		RGB(203, 213, 225),
		RGB(248, 250, 252),
		RGB(22, 163, 74),
		RGB(220, 38, 38)
	};
	static const Palette dark {
		RGB(15, 23, 42),
		RGB(30, 41, 59),
		RGB(226, 232, 240),
		RGB(148, 163, 184),
		RGB(96, 165, 250),
		RGB(59, 130, 246),
		RGB(37, 99, 235),
		RGB(71, 85, 105),
		RGB(24, 34, 53),
		RGB(74, 222, 128),
		RGB(248, 113, 113)
	};
	static Palette highContrast {};
	if(isHighContrast()) {
		highContrast.window = ::GetSysColor(COLOR_WINDOW);
		highContrast.panel = ::GetSysColor(COLOR_WINDOW);
		highContrast.text = ::GetSysColor(COLOR_WINDOWTEXT);
		highContrast.muted = ::GetSysColor(COLOR_GRAYTEXT);
		highContrast.accent = ::GetSysColor(COLOR_HIGHLIGHT);
		highContrast.accentHot = ::GetSysColor(COLOR_HIGHLIGHT);
		highContrast.accentPressed = ::GetSysColor(COLOR_HIGHLIGHT);
		highContrast.border = ::GetSysColor(COLOR_WINDOWTEXT);
		highContrast.rowAlternate = ::GetSysColor(COLOR_WINDOW);
		highContrast.success = ::GetSysColor(COLOR_WINDOWTEXT);
		highContrast.danger = ::GetSysColor(COLOR_WINDOWTEXT);
		return highContrast;
	}
	return isDarkMode() ? dark : light;
}

inline COLORREF blend(COLORREF base, COLORREF overlay, BYTE overlayWeight) {
	const auto baseWeight = static_cast<BYTE>(255 - overlayWeight);
	return RGB(
		(GetRValue(base) * baseWeight + GetRValue(overlay) * overlayWeight) / 255,
		(GetGValue(base) * baseWeight + GetGValue(overlay) * overlayWeight) / 255,
		(GetBValue(base) * baseWeight + GetBValue(overlay) * overlayWeight) / 255
	);
}

inline COLORREF textOn(COLORREF background) {
	const unsigned luminance =
		GetRValue(background) * 299 +
		GetGValue(background) * 587 +
		GetBValue(background) * 114;
	return luminance < 150000 ? RGB(255, 255, 255) : RGB(15, 23, 42);
}

template<typename WidgetPointer>
inline void styleSurface(WidgetPointer widget, COLORREF background = palette().window,
	COLORREF foreground = palette().text)
{
	if(!widget) {
		return;
	}

	widget->setColor(foreground, background);
	widget->onEraseBackground([widget, background](dwt::Canvas& canvas) {
		dwt::Brush brush(background);
		canvas.fill(dwt::Rectangle(widget->getClientSize()), brush);
		return true;
	});
}

inline void drawGroupBox(dwt::Canvas& canvas, dwt::GroupBoxPtr group) {
	const auto& colors = palette();
	const auto bounds = dwt::Rectangle(group->getClientSize());
	dwt::Brush backgroundBrush(colors.window);
	canvas.fill(bounds, backgroundBrush);

	auto fontSelection = canvas.select(*group->getFont());
	const auto caption = group->getText();
	const auto textSize = canvas.getTextExtent(caption);
	const long frameTop = std::max(1L, textSize.y / 2);
	const dwt::Rectangle frame(
		0,
		frameTop,
		std::max(0L, bounds.width() - 1),
		std::max(0L, bounds.height() - frameTop - 1));
	{
		dwt::Pen borderPen(colors.border, dwt::Pen::Solid, 1);
		dwt::Brush hollowBrush(
			static_cast<HBRUSH>(::GetStockObject(HOLLOW_BRUSH)), false);
		auto penSelection = canvas.select(borderPen);
		auto brushSelection = canvas.select(hollowBrush);
		canvas.rectangle(frame);
	}

	if(!caption.empty()) {
		const auto captionBackground = dwt::Rectangle(
			group->scale(8), 0, textSize.x + group->scale(10),
			textSize.y + group->scale(2));
		canvas.fill(captionBackground, backgroundBrush);

		dwt::Rectangle textRect(group->scale(13), 0,
			textSize.x + group->scale(2), textSize.y + group->scale(2));
		auto backgroundMode = canvas.setBkMode(true);
		canvas.setTextColor(group->getEnabled() ? colors.text : colors.muted);
		canvas.drawText(caption, textRect,
			DT_LEFT | DT_TOP | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
	}
}

inline void refreshGroupBox(dwt::GroupBoxPtr group) {
	if(group) {
		group->setColor(palette().text, palette().window);
		group->redraw(true);
	}
}

inline void styleGroupBox(dwt::GroupBoxPtr group) {
	if(!group) {
		return;
	}
	group->onPainting([group](dwt::PaintCanvas& canvas) {
		drawGroupBox(canvas, group);
	});
	group->onPrinting([group](dwt::Canvas& canvas) {
		drawGroupBox(canvas, group);
	});
	refreshGroupBox(group);
}

inline LRESULT drawCheckBox(NMCUSTOMDRAW& data, dwt::CheckBoxPtr checkBox) {
	if(data.dwDrawStage != CDDS_PREPAINT) {
		return CDRF_DODEFAULT;
	}

	const auto& colors = palette();
	const bool disabled = !checkBox->getEnabled() ||
		(data.uItemState & CDIS_DISABLED) != 0;
	const bool pressed = (data.uItemState & CDIS_SELECTED) != 0;
	const bool hot = (data.uItemState & CDIS_HOT) != 0;
	const bool focused = (data.uItemState & CDIS_FOCUS) != 0;
	const bool checked =
		Button_GetCheck(data.hdr.hwndFrom) == BST_CHECKED;

	dwt::FreeCanvas canvas(data.hdc);
	dwt::Rectangle bounds(data.rc);
	dwt::Brush backgroundBrush(colors.window);
	canvas.fill(bounds, backgroundBrush);

	const long preferredBoxSize = checkBox->scale(15);
	const long boxSize = std::max(8L,
		std::min(preferredBoxSize, std::max(8L, bounds.height() - 4)));
	const long boxTop = bounds.top() + std::max(0L, (bounds.height() - boxSize) / 2);
	const dwt::Rectangle boxRect(bounds.left() + 1, boxTop, boxSize, boxSize);

	COLORREF boxBackground = checked ? colors.accent : colors.panel;
	COLORREF boxBorder = checked ? colors.accent : colors.border;
	if(pressed) {
		boxBackground = checked ? colors.accentPressed :
			blend(colors.panel, colors.accent, 38);
	} else if(hot) {
		boxBackground = checked ? colors.accentHot :
			blend(colors.panel, colors.accent, 18);
		boxBorder = blend(boxBorder, colors.accent, 110);
	}
	if(disabled) {
		boxBackground = blend(boxBackground, colors.window, 120);
		boxBorder = blend(boxBorder, colors.window, 90);
	}

	{
		dwt::Brush boxBrush(boxBackground);
		dwt::Pen borderPen(boxBorder, dwt::Pen::Solid, 1);
		auto brushSelection = canvas.select(boxBrush);
		auto penSelection = canvas.select(borderPen);
		canvas.rectangle(boxRect);
	}

	if(checked) {
		const auto checkColor = disabled ?
			blend(RGB(255, 255, 255), boxBackground, 105) :
			RGB(255, 255, 255);
		dwt::Pen checkPen(checkColor, dwt::Pen::Solid,
			std::max(1, checkBox->scale(2)));
		auto penSelection = canvas.select(checkPen);
		canvas.line(
			dwt::Point(boxRect.left() + boxSize / 4, boxRect.top() + boxSize / 2),
			dwt::Point(boxRect.left() + boxSize * 2 / 5, boxRect.bottom() - boxSize / 4));
		canvas.line(
			dwt::Point(boxRect.left() + boxSize * 2 / 5, boxRect.bottom() - boxSize / 4),
			dwt::Point(boxRect.right() - boxSize / 5, boxRect.top() + boxSize / 4));
	}

	const long textLeft = boxRect.right() + checkBox->scale(8);
	auto fontSelection = canvas.select(*checkBox->getFont());
	const auto caption = checkBox->getText();
	const auto textSize = canvas.getTextExtent(caption);
	const long textTop = bounds.top() +
		std::max(0L, (bounds.height() - textSize.y) / 2);
	dwt::Rectangle textRect(
		textLeft,
		textTop,
		std::max(0L, bounds.right() - textLeft),
		std::max(0L, bounds.bottom() - textTop));
	auto backgroundMode = canvas.setBkMode(true);
	canvas.setTextColor(disabled ? colors.muted : colors.text);
	canvas.drawText(caption, textRect,
		DT_LEFT | DT_TOP | DT_SINGLELINE | DT_END_ELLIPSIS);

	if(focused && !disabled) {
		const long focusTop = std::max(bounds.top(), textTop - 1);
		dwt::Rectangle focusRect(
			std::max(bounds.left(), textLeft - 2),
			focusTop,
			std::min(textRect.width(), textSize.x + 4),
			std::min(bounds.bottom() - focusTop, textSize.y + 2));
		dwt::Pen focusPen(colors.muted, dwt::Pen::Dot, 1);
		auto penSelection = canvas.select(focusPen);
		canvas.line(focusRect);
	}

	return CDRF_SKIPDEFAULT;
}

inline void refreshCheckBox(dwt::CheckBoxPtr checkBox) {
	if(checkBox) {
		checkBox->setColor(palette().text, palette().window);
		checkBox->redraw(true);
	}
}

inline void styleCheckBox(dwt::CheckBoxPtr checkBox) {
	if(!checkBox) {
		return;
	}
	checkBox->onCustomDraw([checkBox](NMCUSTOMDRAW& data) {
		return drawCheckBox(data, checkBox);
	});
	refreshCheckBox(checkBox);
}

inline void drawComboBox(dwt::Canvas& canvas, dwt::ComboBoxPtr combo) {
	const auto& colors = palette();
	const auto bounds = dwt::Rectangle(combo->getClientSize());
	const bool disabled = !combo->getEnabled();
	const bool focused = ::GetFocus() == combo->handle();
	const bool dropped = combo->sendMessage(CB_GETDROPPEDSTATE) != FALSE;

	const auto background = disabled ?
		blend(colors.panel, colors.window, 110) : colors.panel;
	const auto foreground = disabled ? colors.muted : colors.text;
	const auto border = focused || dropped ? colors.accent : colors.border;
	const long arrowWidth = std::min(
		std::max(static_cast<long>(combo->scale(22)), bounds.height()),
		std::max(0L, bounds.width()));
	const long arrowLeft = std::max(bounds.left(), bounds.right() - arrowWidth);

	dwt::Brush backgroundBrush(background);
	canvas.fill(bounds, backgroundBrush);

	dwt::Rectangle arrowRect(
		arrowLeft, bounds.top(), arrowWidth, bounds.height());
	if(dropped) {
		dwt::Brush arrowBackground(blend(background, colors.accent, 32));
		canvas.fill(arrowRect, arrowBackground);
	}

	{
		dwt::Pen separatorPen(colors.border, dwt::Pen::Solid, 1);
		auto penSelection = canvas.select(separatorPen);
		canvas.line(
			dwt::Point(arrowLeft, bounds.top() + 1),
			dwt::Point(arrowLeft, bounds.bottom() - 1));
	}

	const long arrowCenterX = arrowLeft + arrowWidth / 2;
	const long arrowCenterY = bounds.top() + bounds.height() / 2;
	const long arrowHalfWidth = std::max(3, combo->scale(4));
	const long arrowHalfHeight = std::max(2, combo->scale(2));
	POINT arrow[] {
		{ arrowCenterX - arrowHalfWidth, arrowCenterY - arrowHalfHeight },
		{ arrowCenterX + arrowHalfWidth, arrowCenterY - arrowHalfHeight },
		{ arrowCenterX, arrowCenterY + arrowHalfHeight }
	};
	{
		dwt::Pen arrowPen(foreground, dwt::Pen::Solid, 1);
		dwt::Brush arrowBrush(foreground);
		auto penSelection = canvas.select(arrowPen);
		auto brushSelection = canvas.select(arrowBrush);
		canvas.polygon(arrow, 3);
	}

	dwt::tstring text;
	const int selected = combo->getSelected();
	if(selected >= 0) {
		text = combo->getValue(selected);
	} else {
		text = combo->getText();
	}
	dwt::Rectangle textRect(
		bounds.left() + combo->scale(8),
		bounds.top(),
		std::max(0L, arrowLeft - bounds.left() - combo->scale(12)),
		bounds.height());
	auto fontSelection = canvas.select(*combo->getFont());
	auto backgroundMode = canvas.setBkMode(true);
	canvas.setTextColor(foreground);
	canvas.drawText(text, textRect,
		DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

	{
		dwt::Pen borderPen(border, dwt::Pen::Solid, 1);
		dwt::Brush hollowBrush(
			static_cast<HBRUSH>(::GetStockObject(HOLLOW_BRUSH)), false);
		auto penSelection = canvas.select(borderPen);
		auto brushSelection = canvas.select(hollowBrush);
		dwt::Rectangle frame = bounds;
		frame.size -= dwt::Point(1, 1);
		canvas.rectangle(frame);
	}
}

inline void refreshComboBox(dwt::ComboBoxPtr combo) {
	if(!combo) {
		return;
	}

	combo->setColor(palette().text, palette().panel);
	ScrollBarStyle::apply(combo);
	if(auto list = combo->getListBox()) {
		list->setColor(palette().text, palette().panel);
		ScrollBarStyle::apply(list);
		list->redraw(true);
	}
	if(auto text = combo->getTextBox()) {
		text->setColor(palette().text, palette().panel);
		text->redraw(true);
	}
	combo->redraw(true);
}

inline void styleComboBox(dwt::ComboBoxPtr combo) {
	if(!combo) {
		return;
	}
	combo->onPainting([combo](dwt::PaintCanvas& canvas) {
		drawComboBox(canvas, combo);
	});
	combo->onPrinting([combo](dwt::Canvas& canvas) {
		drawComboBox(canvas, combo);
	});
	refreshComboBox(combo);
}

inline dwt::FontPtr makeFont(unsigned dpi, int points = 9, int weight = FW_NORMAL,
	const TCHAR* face = _T("Segoe UI"))
{
	LOGFONT font {};
	font.lfHeight = -::MulDiv(points, static_cast<int>(dpi), 72);
	font.lfWeight = weight;
	font.lfQuality = CLEARTYPE_QUALITY;
	_tcsncpy_s(font.lfFaceName, LF_FACESIZE, face, _TRUNCATE);
	return dwt::FontPtr(new dwt::Font(font));
}

enum class ButtonTone {
	Neutral,
	Primary,
	Danger
};

inline LRESULT drawButton(NMCUSTOMDRAW& data, dwt::ButtonPtr button,
	ButtonTone tone)
{
	if(data.dwDrawStage != CDDS_PREPAINT) {
		return CDRF_DODEFAULT;
	}

	const auto& colors = palette();
	const bool disabled = (data.uItemState & CDIS_DISABLED) != 0;
	const bool pressed = (data.uItemState & CDIS_SELECTED) != 0;
	const bool hot = (data.uItemState & CDIS_HOT) != 0;
	const bool focused = (data.uItemState & CDIS_FOCUS) != 0;

	COLORREF background = colors.panel;
	COLORREF foreground = colors.text;
	COLORREF border = colors.border;

	if(tone == ButtonTone::Primary) {
		background = pressed ? colors.accentPressed : (hot ? colors.accentHot : colors.accent);
		foreground = RGB(255, 255, 255);
		border = background;
	} else if(tone == ButtonTone::Danger) {
		background = pressed ? blend(colors.panel, colors.danger, 42) :
			(hot ? blend(colors.panel, colors.danger, 25) : colors.panel);
		foreground = colors.danger;
		border = blend(colors.border, colors.danger, hot ? 145 : 90);
	} else if(pressed || hot) {
		background = blend(colors.panel, colors.accent, pressed ? 38 : 20);
		border = blend(colors.border, colors.accent, hot ? 100 : 70);
	}

	if(disabled) {
		background = blend(colors.panel, colors.window, 120);
		foreground = blend(colors.muted, colors.panel, 100);
		border = blend(colors.border, colors.panel, 80);
	}

	dwt::FreeCanvas canvas(data.hdc);
	dwt::Rectangle bounds(data.rc);
	dwt::Brush backgroundBrush(background);
	canvas.fill(bounds, backgroundBrush);
	{
		dwt::Pen borderPen(border, dwt::Pen::Solid, 1);
		dwt::Brush hollowBrush(
			static_cast<HBRUSH>(::GetStockObject(HOLLOW_BRUSH)), false);
		auto penSelection = canvas.select(borderPen);
		auto brushSelection = canvas.select(hollowBrush);
		canvas.rectangle(bounds);
	}

	TCHAR caption[256] {};
	::GetWindowText(data.hdr.hwndFrom, caption, 255);
	dwt::Rectangle textRect(data.rc);
	if(pressed) {
		textRect.pos += dwt::Point(1, 1);
	}
	auto fontSelection = canvas.select(*button->getFont());
	auto backgroundMode = canvas.setBkMode(true);
	canvas.setTextColor(foreground);
	canvas.drawText(dwt::tstring(caption), textRect,
		DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

	if(focused && !disabled) {
		dwt::Rectangle focusRect(data.rc);
		focusRect.pos += dwt::Point(3, 3);
		focusRect.size -= dwt::Point(6, 6);
		dwt::Pen focusPen(foreground, dwt::Pen::Dot, 1);
		auto focusPenSelection = canvas.select(focusPen);
		canvas.line(focusRect);
	}

	return CDRF_SKIPDEFAULT;
}

inline void styleButton(dwt::ButtonPtr button, ButtonTone tone = ButtonTone::Neutral) {
	if(button) {
		button->onCustomDraw([button, tone](NMCUSTOMDRAW& data) {
			return drawButton(data, button, tone);
		});
	}
}

inline LRESULT drawColorButton(NMCUSTOMDRAW& data, dwt::ButtonPtr button,
	COLORREF color)
{
	if(data.dwDrawStage != CDDS_PREPAINT) {
		return CDRF_DODEFAULT;
	}

	const bool disabled = (data.uItemState & CDIS_DISABLED) != 0;
	const bool pressed = (data.uItemState & CDIS_SELECTED) != 0;
	const bool hot = (data.uItemState & CDIS_HOT) != 0;
	const bool focused = (data.uItemState & CDIS_FOCUS) != 0;
	auto background = color;
	if(pressed) {
		background = blend(color, RGB(0, 0, 0), 35);
	} else if(hot) {
		background = blend(color, textOn(color), 22);
	}
	if(disabled) {
		background = blend(color, palette().window, 130);
	}
	const auto foreground = textOn(background);
	const auto border = focused ? palette().accent : palette().border;

	dwt::FreeCanvas canvas(data.hdc);
	dwt::Rectangle bounds(data.rc);
	dwt::Brush backgroundBrush(background);
	canvas.fill(bounds, backgroundBrush);
	{
		dwt::Pen borderPen(border, dwt::Pen::Solid, 1);
		dwt::Brush hollowBrush(
			static_cast<HBRUSH>(::GetStockObject(HOLLOW_BRUSH)), false);
		auto penSelection = canvas.select(borderPen);
		auto brushSelection = canvas.select(hollowBrush);
		canvas.rectangle(bounds);
	}

	TCHAR caption[256] {};
	::GetWindowText(data.hdr.hwndFrom, caption, 255);
	dwt::Rectangle textRect(data.rc);
	if(pressed) {
		textRect.pos += dwt::Point(1, 1);
	}
	auto fontSelection = canvas.select(*button->getFont());
	auto backgroundMode = canvas.setBkMode(true);
	canvas.setTextColor(foreground);
	canvas.drawText(dwt::tstring(caption), textRect,
		DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

	if(focused && !disabled) {
		dwt::Rectangle focusRect(data.rc);
		focusRect.pos += dwt::Point(3, 3);
		focusRect.size -= dwt::Point(6, 6);
		dwt::Pen focusPen(foreground, dwt::Pen::Dot, 1);
		auto focusPenSelection = canvas.select(focusPen);
		canvas.line(focusRect);
	}

	return CDRF_SKIPDEFAULT;
}

inline void styleColorButton(dwt::ButtonPtr button, std::function<COLORREF()> color) {
	if(button) {
		button->onCustomDraw([button, color](NMCUSTOMDRAW& data) {
			return drawColorButton(data, button, color());
		});
	}
}

} // namespace ui

#endif
