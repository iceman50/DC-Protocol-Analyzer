/*
 * Copyright (C) 2026 iceman50
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "stdafx.h"
#include "CustomTitleBar.h"
#include "UIStyles.h"

#include <dwt/CanvasClasses.h>
#include <dwt/DWTException.h>
#include <dwt/Message.h>
#include <dwt/resources/Brush.h>
#include <dwt/resources/Pen.h>
#include <dwt/widgets/Button.h>
#include <dwt/widgets/Frame.h>
#include <dwt/widgets/Grid.h>

#include <algorithm>
#include <utility>
#include <vector>

namespace ui {

namespace {

bool rootIsActive(HWND root) {
	const auto foreground = ::GetForegroundWindow();
	return foreground &&
		::GetAncestor(foreground, GA_ROOTOWNER) ==
			::GetAncestor(root, GA_ROOTOWNER);
}

} // unnamed namespace

CustomTitleBar::CustomTitleBar(dwt::Frame* owner_,
	const dwt::FontPtr& font, std::function<void ()> closeAction_) :
	owner(owner_),
	bar(nullptr),
	minimizeButton(nullptr),
	maximizeButton(nullptr),
	closeButton(nullptr),
	closeAction(std::move(closeAction_)),
	active(false)
{
	if(!owner || !::IsWindow(owner->handle())) {
		throw dwt::DWTException("CustomTitleBar requires a created top-level window");
	}

	const auto style = static_cast<DWORD>(
		::GetWindowLongPtr(owner->handle(), GWL_STYLE));
	const bool hasMinimize = (style & WS_MINIMIZEBOX) != 0;
	const bool hasMaximize = (style & WS_MAXIMIZEBOX) != 0;
	const size_t buttonCount =
		static_cast<size_t>(hasMinimize) +
		static_cast<size_t>(hasMaximize) + 1;

	bar = owner->addChild(dwt::Grid::Seed(1, buttonCount + 1));
	bar->row(0).mode = dwt::GridInfo::FILL;
	bar->column(0).mode = dwt::GridInfo::FILL;
	bar->setSpacing(0);
	bar->setFont(font);
	bar->setAccessibleName(_T("Application title bar"));

	size_t column = 1;
	if(hasMinimize) {
		minimizeButton = addButton(
			_T("Minimize"), ButtonRole::Minimize, font, column++);
	}
	if(hasMaximize) {
		maximizeButton = addButton(
			_T("Maximize"), ButtonRole::MaximizeRestore, font, column++);
	}
	closeButton = addButton(_T("Close"), ButtonRole::Close, font, column);

	bar->onPainting([this](dwt::PaintCanvas& canvas) { paint(canvas); });
	bar->onPrinting([this](dwt::Canvas& canvas) { paint(canvas); });

	// Let uncovered parts of the child strip fall through to the top-level
	// window, whose HTCAPTION result gives us native move, snap, double-click,
	// and system-menu behavior.
	bar->onRaw([](WPARAM, LPARAM) -> LRESULT {
		return HTTRANSPARENT;
	}, dwt::Message(WM_NCHITTEST));

	// Make the complete restored window client area paintable. This removes the
	// native sizing frame visually; resize behavior is restored by hitTest.
	owner->onRaw([this](WPARAM wParam, LPARAM lParam) -> LRESULT {
		return calculateClientArea(wParam, lParam);
	}, dwt::Message(WM_NCCALCSIZE));
	owner->onRaw([](WPARAM, LPARAM) -> LRESULT {
		return 0;
	}, dwt::Message(WM_NCPAINT));
	owner->onRaw([this](WPARAM wParam, LPARAM) -> LRESULT {
		active = wParam != FALSE;
		refresh();
		return TRUE;
	}, dwt::Message(WM_NCACTIVATE));
	owner->onRaw([this](WPARAM wParam, LPARAM lParam) -> LRESULT {
		return hitTest(wParam, lParam);
	}, dwt::Message(WM_NCHITTEST));

	owner->addCallback(dwt::Message(WM_ACTIVATE),
		[this](const MSG& message, LRESULT&) -> bool {
			active = LOWORD(message.wParam) != WA_INACTIVE;
			refresh();
			return false;
		});
	owner->onSized([this](const dwt::SizedEvent&) {
		layout();
		updateMaximizeButton();
	});
	owner->onDpiChanged([this](const dwt::DpiChangedEvent&) {
		layout();
		refresh();
	});
	owner->onThemeChanged([this] { refresh(); });
	owner->onSystemColorsChanged([this] { refresh(); });
	owner->onSystemSettingsChanged(
		[this](const dwt::SystemSettingsEvent&) { refresh(); });

	active = rootIsActive(owner->handle());

	::SetLastError(ERROR_SUCCESS);
	const auto previousStyle = ::SetWindowLongPtr(owner->handle(), GWL_STYLE,
		static_cast<LONG_PTR>(style & ~WS_CAPTION));
	if(!previousStyle && ::GetLastError() != ERROR_SUCCESS) {
		throw dwt::Win32Exception("Unable to remove the native window caption");
	}

	const auto exStyle = static_cast<DWORD>(
		::GetWindowLongPtr(owner->handle(), GWL_EXSTYLE));
	::SetLastError(ERROR_SUCCESS);
	const auto previousExStyle = ::SetWindowLongPtr(owner->handle(), GWL_EXSTYLE,
		static_cast<LONG_PTR>(exStyle &
			~(WS_EX_CLIENTEDGE | WS_EX_DLGMODALFRAME |
				WS_EX_STATICEDGE | WS_EX_WINDOWEDGE)));
	if(!previousExStyle && ::GetLastError() != ERROR_SUCCESS) {
		throw dwt::Win32Exception("Unable to remove the native window edge");
	}
	if(!::SetWindowPos(owner->handle(), nullptr, 0, 0, 0, 0,
		SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE |
			SWP_NOOWNERZORDER | SWP_NOZORDER))
	{
		throw dwt::Win32Exception("Unable to apply the custom window caption");
	}

	layout();
	updateMaximizeButton();
}

long CustomTitleBar::height() const {
	return owner ? owner->scale(logicalHeight) : logicalHeight;
}

void CustomTitleBar::layout() {
	if(!owner || !bar || !::IsWindow(owner->handle()) ||
		!::IsWindow(bar->handle()))
	{
		return;
	}

	const auto client = owner->getClientSize();
	bar->resize(dwt::Rectangle(
		0, 0, std::max(0L, client.x), height()));
}

void CustomTitleBar::refresh() {
	if(!bar || !::IsWindow(bar->handle())) {
		return;
	}
	::RedrawWindow(bar->handle(), nullptr, nullptr,
		RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
}

dwt::ButtonPtr CustomTitleBar::addButton(const dwt::tstring& caption,
	ButtonRole role, const dwt::FontPtr& font, size_t column)
{
	dwt::Button::Seed seed(caption, BS_FLAT);
	seed.style &= ~WS_TABSTOP;
	seed.font = font;
	seed.padding = dwt::Point();
	auto button = bar->addChild(seed);
	bar->column(column).mode = dwt::GridInfo::STATIC;
	bar->column(column).size = logicalButtonWidth;
	bar->setWidget(button, 0, column);
	button->setAccessibleName(caption);
	button->onCustomDraw([this, button, role](NMCUSTOMDRAW& data) {
		return drawButton(data, button, role);
	});
	button->onRaw([this](WPARAM, LPARAM lParam) -> LRESULT {
		return resizeHitTest(lParam) == HTCLIENT ?
			HTCLIENT : HTTRANSPARENT;
	}, dwt::Message(WM_NCHITTEST));

	switch(role) {
	case ButtonRole::Minimize:
		button->onClicked([this] {
			owner->sendMessage(WM_SYSCOMMAND, SC_MINIMIZE, 0);
		});
		break;

	case ButtonRole::MaximizeRestore:
		button->onClicked([this] {
			owner->sendMessage(WM_SYSCOMMAND,
				::IsZoomed(owner->handle()) ? SC_RESTORE : SC_MAXIMIZE, 0);
		});
		break;

	case ButtonRole::Close:
		button->onClicked([this] {
			if(closeAction) {
				// The monitor supplies GUI::close here so its custom caption
				// follows the verified hide/re-show lifecycle directly.
				closeAction();
			} else {
				// Modal dialogs retain their normal DWT close lifecycle.
				owner->sendMessage(WM_CLOSE, 0, 0);
			}
		});
		break;
	}

	return button;
}

LRESULT CustomTitleBar::calculateClientArea(WPARAM wParam,
	LPARAM lParam) const
{
	if(!owner || !wParam || !lParam) {
		return 0;
	}

	// A maximized WS_THICKFRAME window is normally larger than rcWork by the
	// invisible resize frame. Keep our custom client inside the monitor work
	// area so it does not extend behind the taskbar.
	if(::IsZoomed(owner->handle())) {
		auto params = reinterpret_cast<NCCALCSIZE_PARAMS*>(lParam);
		MONITORINFO monitorInfo { sizeof(MONITORINFO) };
		const auto monitor = ::MonitorFromWindow(
			owner->handle(), MONITOR_DEFAULTTONEAREST);
		if(monitor && ::GetMonitorInfo(monitor, &monitorInfo)) {
			params->rgrc[0] = monitorInfo.rcWork;
		}
	}
	return 0;
}

void CustomTitleBar::paint(dwt::Canvas& canvas) {
	if(!owner || !bar) {
		return;
	}

	const auto& colors = palette();
	const dwt::Rectangle bounds(bar->getClientSize());
	dwt::Brush background(colors.window);
	canvas.fill(bounds, background);

	const long iconSize = bar->scale(16);
	const long leftInset = bar->scale(12);
	long textLeft = leftInset;
	if(const auto icon = getSmallIcon()) {
		const long iconTop = std::max(0L, (bounds.height() - iconSize) / 2);
		::DrawIconEx(canvas.handle(), leftInset, iconTop, icon,
			iconSize, iconSize, 0, nullptr, DI_NORMAL);
		textLeft += iconSize + bar->scale(8);
	}

	const long buttonsWidth =
		bar->scale(logicalButtonWidth) *
		(static_cast<long>(minimizeButton != nullptr) +
			static_cast<long>(maximizeButton != nullptr) + 1);
	dwt::Rectangle titleRect(
		textLeft, 0,
		std::max(0L, bounds.width() - textLeft - buttonsWidth -
			bar->scale(8)),
		bounds.height());
	auto fontSelection = canvas.select(*bar->getFont());
	auto backgroundMode = canvas.setBkMode(true);
	canvas.setTextColor(active ? colors.text : colors.muted);
	canvas.drawText(owner->getText(), titleRect,
		DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS |
			DT_NOPREFIX);

	dwt::Pen separator(colors.border, dwt::Pen::Solid, 1);
	auto separatorSelection = canvas.select(separator);
	canvas.line(dwt::Point(0, std::max(0L, bounds.bottom() - 1)),
		dwt::Point(bounds.right(), std::max(0L, bounds.bottom() - 1)));
}

LRESULT CustomTitleBar::hitTest(WPARAM wParam, LPARAM lParam) const {
	if(!owner || !bar) {
		return HTNOWHERE;
	}

	const auto resize = resizeHitTest(lParam);
	if(resize != HTCLIENT) {
		return resize;
	}

	POINT point { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
	if(!::ScreenToClient(owner->handle(), &point)) {
		return HTNOWHERE;
	}
	const auto client = owner->getClientSize();
	if(point.x < 0 || point.x >= client.x ||
		point.y < 0 || point.y >= height())
	{
		return HTCLIENT;
	}

	if(getSmallIcon() && point.x < bar->scale(40)) {
		return HTSYSMENU;
	}
	return HTCAPTION;
}

LRESULT CustomTitleBar::resizeHitTest(LPARAM lParam) const {
	if(!owner || !::IsWindow(owner->handle()) ||
		::IsZoomed(owner->handle()))
	{
		return HTCLIENT;
	}

	const auto style = static_cast<DWORD>(
		::GetWindowLongPtr(owner->handle(), GWL_STYLE));
	if((style & WS_THICKFRAME) == 0) {
		return HTCLIENT;
	}

	POINT point { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
	if(!::ScreenToClient(owner->handle(), &point)) {
		return HTNOWHERE;
	}
	const auto client = owner->getClientSize();
	const long frameX = std::max(1,
		owner->getSystemMetric(SM_CXSIZEFRAME) +
			owner->getSystemMetric(SM_CXPADDEDBORDER));
	const long frameY = std::max(1,
		owner->getSystemMetric(SM_CYSIZEFRAME) +
			owner->getSystemMetric(SM_CXPADDEDBORDER));
	const bool left = point.x >= 0 && point.x < frameX;
	const bool right = point.x < client.x && point.x >= client.x - frameX;
	const bool top = point.y >= 0 && point.y < frameY;
	const bool bottom = point.y < client.y && point.y >= client.y - frameY;

	if(top && left) return HTTOPLEFT;
	if(top && right) return HTTOPRIGHT;
	if(bottom && left) return HTBOTTOMLEFT;
	if(bottom && right) return HTBOTTOMRIGHT;
	if(left) return HTLEFT;
	if(right) return HTRIGHT;
	if(top) return HTTOP;
	if(bottom) return HTBOTTOM;
	return HTCLIENT;
}

LRESULT CustomTitleBar::drawButton(NMCUSTOMDRAW& data,
	dwt::ButtonPtr button, ButtonRole role) const
{
	if(data.dwDrawStage != CDDS_PREPAINT) {
		return CDRF_DODEFAULT;
	}

	const auto& colors = palette();
	const bool pressed = (data.uItemState & CDIS_SELECTED) != 0;
	const bool hot = (data.uItemState & CDIS_HOT) != 0;
	COLORREF background = colors.window;
	COLORREF foreground = active ? colors.text : colors.muted;

	if(role == ButtonRole::Close && (hot || pressed)) {
		background = pressed ? RGB(153, 27, 27) : RGB(196, 43, 28);
		foreground = RGB(255, 255, 255);
	} else if(hot || pressed) {
		background = blend(colors.window, colors.text, pressed ? 45 : 25);
	}

	dwt::FreeCanvas canvas(data.hdc);
	const dwt::Rectangle bounds(data.rc);
	dwt::Brush backgroundBrush(background);
	canvas.fill(bounds, backgroundBrush);

	const long centerX = bounds.left() + bounds.width() / 2;
	const long centerY = bounds.top() + bounds.height() / 2;
	const long half = std::max(4, button->scale(5));
	dwt::Pen glyph(foreground, dwt::Pen::Solid,
		std::max(1, button->scale(1)));
	auto glyphSelection = canvas.select(glyph);

	switch(role) {
	case ButtonRole::Minimize:
		canvas.line(dwt::Point(centerX - half, centerY + half / 2),
			dwt::Point(centerX + half, centerY + half / 2));
		break;

	case ButtonRole::MaximizeRestore:
		if(owner && ::IsZoomed(owner->handle())) {
			const long offset = std::max(2, button->scale(2));
			canvas.line(dwt::Rectangle(
				centerX - half + offset, centerY - half,
				half * 2, half * 2));
			dwt::Brush cover(background);
			canvas.fill(dwt::Rectangle(
				centerX - half - 1, centerY - half + offset - 1,
				half * 2, half * 2), cover);
			canvas.line(dwt::Rectangle(
				centerX - half - 1, centerY - half + offset - 1,
				half * 2, half * 2));
		} else {
			canvas.line(dwt::Rectangle(
				centerX - half, centerY - half, half * 2, half * 2));
		}
		break;

	case ButtonRole::Close:
		canvas.line(dwt::Point(centerX - half, centerY - half),
			dwt::Point(centerX + half, centerY + half));
		canvas.line(dwt::Point(centerX + half, centerY - half),
			dwt::Point(centerX - half, centerY + half));
		break;
	}

	return CDRF_SKIPDEFAULT;
}

void CustomTitleBar::updateMaximizeButton() {
	if(!maximizeButton || !::IsWindow(maximizeButton->handle()) ||
		!owner || !::IsWindow(owner->handle()))
	{
		return;
	}

	const dwt::tstring caption = ::IsZoomed(owner->handle()) ?
		_T("Restore") : _T("Maximize");
	if(maximizeButton->getText() != caption) {
		maximizeButton->setText(caption);
		maximizeButton->setAccessibleName(caption);
	}
	maximizeButton->redraw(true);
}

HICON CustomTitleBar::getSmallIcon() const {
	if(!owner || !::IsWindow(owner->handle())) {
		return nullptr;
	}

	auto icon = reinterpret_cast<HICON>(
		owner->sendMessage(WM_GETICON, ICON_SMALL, 0));
	if(!icon) {
		icon = reinterpret_cast<HICON>(
			::GetClassLongPtr(owner->handle(), GCLP_HICONSM));
	}
	return icon;
}

} // namespace ui
