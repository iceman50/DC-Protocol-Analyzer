/*
  DC++ Widget Toolkit

  Copyright (c) 2007-2013, Jacek Sieka

  All rights reserved.

  Redistribution and use in source and binary forms, with or without modification,
  are permitted provided that the following conditions are met:

      * Redistributions of source code must retain the above copyright notice,
        this list of conditions and the following disclaimer.
      * Redistributions in binary form must reproduce the above copyright notice,
        this list of conditions and the following disclaimer in the documentation
        and/or other materials provided with the distribution.
      * Neither the name of the DWT nor the names of its contributors
        may be used to endorse or promote products derived from this software
        without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <dwt/widgets/Header.h>

#include <algorithm>
#include <uxtheme.h>

namespace dwt {

const TCHAR Header::windowClass[] = WC_HEADER;

namespace {

template<typename T, typename F>
void addHeaderNotify(Header* header, int code, F f) {
	header->addCallback(Message(WM_NOTIFY, code),
		[f](const MSG& msg, LRESULT&) -> bool {
			auto data = reinterpret_cast<const T*>(msg.lParam);
			if(!data) {
				return false;
			}
			f(*data);
			return true;
		});
}

template<typename T, typename F>
void addHeaderVetoNotify(Header* header, int code, F f) {
	header->addCallback(Message(WM_NOTIFY, code),
		[f](const MSG& msg, LRESULT& result) -> bool {
			auto data = reinterpret_cast<const T*>(msg.lParam);
			if(!data) {
				return false;
			}
			result = f(*data) ? FALSE : TRUE;
			return true;
		});
}

}

Header::Seed::Seed() :
	/// @todo add HDS_DRAGDROP when the tree has better support for col ordering
	BaseType::Seed(WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | HDS_HORZ),
	font(0)
{
}

void Header::create( const Header::Seed & cs ) {
	BaseType::create(cs);
	setFont(cs.font);
	applyFilterStyles();
}

Point Header::getPreferredSize() {
	const auto available = getParent() ?
		getParent()->getClientSize() : getPrimaryDesktopSize();
	RECT rc = { 0, 0, available.x, available.y };
	WINDOWPOS wp = { 0 };
	HDLAYOUT hl = { &rc, &wp };
	if(Header_Layout(handle(), &hl)) {
		return Point(wp.cx, wp.cy);
	}

	return Point(0, 0);
}

int Header::insert(const tstring& header, int width, LPARAM lParam, int after) {
	if(after == -1) after = static_cast<int>(size());

	HDITEM item = { HDI_FORMAT };
	item.fmt = HDF_LEFT;// TODO
	item.lParam = lParam;
	if(!header.empty()) {
		item.mask |= HDI_TEXT;
		item.pszText = const_cast<LPTSTR>(header.c_str());
	}

	if(width >= 0) {
		item.mask |= HDI_WIDTH;
		item.cxy = width;
	}

	item.mask |= HDI_LPARAM;

	const auto index = Header_InsertItem(handle(), after, &item);
	applyFilterStyles();
	return index;
}

namespace {

BOOL CALLBACK styleHeaderFilterChild(HWND child, LPARAM fontParam) {
	if(fontParam) {
		::SendMessage(child, WM_SETFONT, static_cast<WPARAM>(fontParam), TRUE);
	}
	::SetWindowTheme(child, L"Explorer", nullptr);
	return TRUE;
}

}

void Header::applyFilterStyles() {
	if(!handle()) {
		return;
	}

	auto currentFont = getFont();
	::EnumChildWindows(handle(), styleHeaderFilterChild,
		reinterpret_cast<LPARAM>(currentFont ? currentFont->handle() : nullptr));
}

void Header::setFontImpl() {
	BaseType::setFontImpl();
	applyFilterStyles();
}

void Header::setFilterBar(bool value) {
	addRemoveStyle(HDS_FILTERBAR, value);
	applyFilterStyles();
}

bool Header::handleMessage(const MSG& msg, LRESULT& retVal) {
	auto handled = BaseType::handleMessage(msg, retVal);
	if(msg.message == WM_PARENTNOTIFY && LOWORD(msg.wParam) == WM_CREATE) {
		auto currentFont = getFont();
		if(HWND child = reinterpret_cast<HWND>(msg.lParam)) {
			styleHeaderFilterChild(child,
				reinterpret_cast<LPARAM>(currentFont ? currentFont->handle() : nullptr));
		}
		applyFilterStyles();
	} else if(msg.message == WM_THEMECHANGED || msg.message == WM_SETTINGCHANGE ||
		msg.message == WM_SYSCOLORCHANGE) {
		applyFilterStyles();
	}
	return handled;
}

int Header::findDataImpl(LPARAM data, int start) {
	for(int i = std::max(start + 1, 0), n = static_cast<int>(size()); i < n; ++i) {
		if(getData(i) == data) {
			return i;
		}
	}
	return -1;
}

LPARAM Header::getDataImpl(int idx) {
	HDITEM item = { HDI_LPARAM };

	if(!Header_GetItem(handle(), idx, &item)) {
		return 0;
	}
	return item.lParam;
}

void Header::setDataImpl(int idx, LPARAM data) {
	HDITEM item = { HDI_LPARAM };
	item.lParam = data;

	Header_SetItem(handle(), idx, &item);
}

int Header::getWidth(int idx) const {
	HDITEM item = { HDI_WIDTH };

	if(!Header_GetItem(handle(), idx, &item)) {
		return 0;
	}
	return item.cxy;
}

tstring Header::getText(int index) const {
	std::vector<TCHAR> text(256);
	for(;;) {
		HDITEM item = { HDI_TEXT };
		item.pszText = text.data();
		item.cchTextMax = static_cast<int>(text.size());
		if(!Header_GetItem(handle(), index, &item)) {
			return tstring();
		}
		if(text.empty() || text.back() == 0) {
			return text.data();
		}
		text.resize(text.size() * 2);
	}
}

int Header::getFormat(int index) const {
	HDITEM item = { HDI_FORMAT };
	return getItem(index, item) ? item.fmt : 0;
}

void Header::clearSortArrows() {
	for(int i = 0, n = static_cast<int>(size()); i < n; ++i) {
		setSortArrow(i, 0);
	}
}

std::vector<int> Header::getOrder() const {
	std::vector<int> order(size());
	if(order.empty()) {
		return order;
	}
	if(!Header_GetOrderArray(handle(), static_cast<int>(order.size()), order.data())) {
		order.clear();
	}
	return order;
}

bool Header::setOrder(const std::vector<int>& order) {
	if(order.empty()) {
		return true;
	}
	return Header_SetOrderArray(handle(), static_cast<int>(order.size()),
		const_cast<int*>(order.data())) == TRUE;
}

void Header::onItemClicked(std::function<void (const NMHEADER&)> f) {
	addHeaderNotify<NMHEADER>(this, HDN_ITEMCLICK, f);
}

void Header::onItemDoubleClicked(std::function<void (const NMHEADER&)> f) {
	addHeaderNotify<NMHEADER>(this, HDN_ITEMDBLCLICK, f);
}

void Header::onDividerDoubleClicked(std::function<void (const NMHEADER&)> f) {
	addHeaderNotify<NMHEADER>(this, HDN_DIVIDERDBLCLICK, f);
}

void Header::onTrack(std::function<void (const NMHEADER&)> f) {
	addHeaderNotify<NMHEADER>(this, HDN_TRACK, f);
}

void Header::onEndTrack(std::function<void (const NMHEADER&)> f) {
	addHeaderNotify<NMHEADER>(this, HDN_ENDTRACK, f);
}

void Header::onEndDrag(std::function<void (const NMHEADER&)> f) {
	addHeaderNotify<NMHEADER>(this, HDN_ENDDRAG, f);
}

void Header::onFilterChanged(std::function<void (const NMHEADER&)> f) {
	addHeaderNotify<NMHEADER>(this, HDN_FILTERCHANGE, f);
}

void Header::onFilterButtonClicked(std::function<void (const NMHDFILTERBTNCLICK&)> f) {
	addHeaderNotify<NMHDFILTERBTNCLICK>(this, HDN_FILTERBTNCLICK, f);
}

void Header::onDropDown(std::function<void (const NMHEADER&)> f) {
	addHeaderNotify<NMHEADER>(this, HDN_DROPDOWN, f);
}

void Header::onOverflowClicked(std::function<void (const NMHEADER&)> f) {
	addHeaderNotify<NMHEADER>(this, HDN_OVERFLOWCLICK, f);
}

void Header::onBeginTrack(std::function<bool (const NMHEADER&)> f) {
	addHeaderVetoNotify<NMHEADER>(this, HDN_BEGINTRACK, f);
}

void Header::onBeginDrag(std::function<bool (const NMHEADER&)> f) {
	addHeaderVetoNotify<NMHEADER>(this, HDN_BEGINDRAG, f);
}

}
