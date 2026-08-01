/*
 * Copyright (C) 2026 iceman50
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef PROTOCOL_ANALYZER_CUSTOM_TITLE_BAR_H
#define PROTOCOL_ANALYZER_CUSTOM_TITLE_BAR_H

#include <dwt/forward.h>
#include <dwt/tstring.h>

#include <functional>

namespace dwt {
class Canvas;
class Frame;
}

namespace ui {

/**
 * A small client-area replacement for the native caption.
 *
 * The complete non-client frame is moved into the client area. WS_THICKFRAME
 * remains in the style for maximize and snap semantics, while this class
 * supplies the resize hit-test codes and paints the complete window surface.
 */
class CustomTitleBar final {
public:
	CustomTitleBar(dwt::Frame* owner, const dwt::FontPtr& font,
		std::function<void ()> closeAction = {});

	CustomTitleBar(const CustomTitleBar&) = delete;
	CustomTitleBar& operator=(const CustomTitleBar&) = delete;

	long height() const;
	void layout();
	void refresh();

private:
	enum class ButtonRole {
		Minimize,
		MaximizeRestore,
		Close
	};

	dwt::ButtonPtr addButton(const dwt::tstring& caption, ButtonRole role,
		const dwt::FontPtr& font, size_t column);
	LRESULT calculateClientArea(WPARAM wParam, LPARAM lParam) const;
	void paint(dwt::Canvas& canvas);
	LRESULT hitTest(WPARAM wParam, LPARAM lParam) const;
	LRESULT resizeHitTest(LPARAM lParam) const;
	LRESULT drawButton(NMCUSTOMDRAW& data, dwt::ButtonPtr button,
		ButtonRole role) const;
	void updateMaximizeButton();
	HICON getSmallIcon() const;

	static constexpr int logicalHeight = 36;
	static constexpr int logicalButtonWidth = 46;

	dwt::Frame* owner;
	dwt::GridPtr bar;
	dwt::ButtonPtr minimizeButton;
	dwt::ButtonPtr maximizeButton;
	dwt::ButtonPtr closeButton;
	std::function<void ()> closeAction;
	bool active;
};

} // namespace ui

#endif
