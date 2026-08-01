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

#include <dwt/widgets/Rebar.h>

namespace dwt {

const TCHAR Rebar::windowClass[] = REBARCLASSNAME;

Rebar::Seed::Seed() :
BaseType::Seed(WS_CHILD | WS_CLIPCHILDREN | CCS_NODIVIDER | RBS_AUTOSIZE | RBS_VARHEIGHT, WS_EX_CONTROLPARENT)
{
}

Rebar::Rebar(Widget* parent) :
BaseType(parent, ChainingDispatcher::superClass<Rebar>()),
imageList(nullptr)
{
}

void Rebar::create(const Seed& cs) {
	BaseType::create(cs);
}

int Rebar::refresh() {
	// use dummy sizes to avoid flickering; the rebar will figure out the proper sizes by itself.
	::MoveWindow(handle(), 0, 0, 0, 0, TRUE);
	return BaseType::getWindowSize().y;
}

void Rebar::add(Widget* w, unsigned style, const tstring& text) {
	if(size() == 0)
		setVisible(true);

	w->addRemoveStyle(CCS_NORESIZE, true);

	REBARBANDINFO info = { sizeof(REBARBANDINFO), RBBIM_CHILD | RBBIM_CHILDSIZE | RBBIM_STYLE, style };

	if(!text.empty()) {
		info.fMask |= RBBIM_TEXT;
		info.lpText = const_cast<LPTSTR>(text.c_str());
	}

	info.hwndChild = w->handle();

	const Point preferredSize = w->getPreferredSize();
	info.cxMinChild = preferredSize.x;
	info.cyMinChild = preferredSize.y;

	if(!sendMessage(RB_INSERTBAND, static_cast<WPARAM>(-1),
		reinterpret_cast<LPARAM>(&info)))
	{
		if(size() == 0) {
			setVisible(false);
		}
		throw Win32Exception("Unable to insert rebar band");
	}
}

void Rebar::remove(Widget* w) {
	for(unsigned i = 0, n = size(); i < n; ++i) {
		REBARBANDINFO info = { sizeof(REBARBANDINFO), RBBIM_CHILD };
		if(sendMessage(RB_GETBANDINFO, i, reinterpret_cast<LPARAM>(&info)) && info.hwndChild == w->handle()) {
			sendMessage(RB_DELETEBAND, i);
			break;
		}
	}

	if(size() == 0)
		setVisible(false);
}

bool Rebar::empty() const {
	return size() == 0;
}

unsigned Rebar::size() const {
	return static_cast<unsigned>(sendMessage(RB_GETBANDCOUNT));
}

int Rebar::indexOf(Widget* widget) const {
	if(!widget) {
		return -1;
	}
	for(unsigned index = 0; index < size(); ++index) {
		REBARBANDINFO info = { sizeof(REBARBANDINFO), RBBIM_CHILD };
		if(sendMessage(RB_GETBANDINFO, index, reinterpret_cast<LPARAM>(&info)) &&
			info.hwndChild == widget->handle())
		{
			return static_cast<int>(index);
		}
	}
	return -1;
}

Rectangle Rebar::getBandRect(unsigned index) const {
	RECT rectangle = { 0 };
	return sendMessage(RB_GETRECT, index, reinterpret_cast<LPARAM>(&rectangle)) ?
		Rectangle(rectangle) : Rectangle();
}

Rectangle Rebar::getBandBorders(unsigned index) const {
	RECT borders = { 0 };
	sendMessage(RB_GETBANDBORDERS, index, reinterpret_cast<LPARAM>(&borders));
	return Rectangle(borders.left, borders.top, borders.right, borders.bottom);
}

int Rebar::getBarHeight() const {
	return static_cast<int>(sendMessage(RB_GETBARHEIGHT));
}

int Rebar::getRowCount() const {
	return static_cast<int>(sendMessage(RB_GETROWCOUNT));
}

int Rebar::getRowHeight(unsigned row) const {
	return static_cast<int>(sendMessage(RB_GETROWHEIGHT, row));
}

COLORREF Rebar::getBackgroundColor() const {
	return static_cast<COLORREF>(sendMessage(RB_GETBKCOLOR));
}

COLORREF Rebar::setBackgroundColor(COLORREF color) {
	return static_cast<COLORREF>(sendMessage(RB_SETBKCOLOR, 0, color));
}

COLORREF Rebar::getTextColor() const {
	return static_cast<COLORREF>(sendMessage(RB_GETTEXTCOLOR));
}

COLORREF Rebar::setTextColor(COLORREF color) {
	return static_cast<COLORREF>(sendMessage(RB_SETTEXTCOLOR, 0, color));
}

DWORD Rebar::getExtendedStyle() const {
	return static_cast<DWORD>(sendMessage(RB_GETEXTENDEDSTYLE));
}

bool Rebar::setImageList(ImageListPtr value) {
	REBARINFO info = { sizeof(REBARINFO), RBIM_IMAGELIST,
		value ? value->handle() : nullptr };
	if(!sendMessage(RB_SETBARINFO, 0, reinterpret_cast<LPARAM>(&info))) {
		return false;
	}
	imageList = value;
	return true;
}

int Rebar::hitTest(const ScreenCoordinate& point, UINT* flags) const {
	RBHITTESTINFO info = { screenToClient(point.getPoint()).toPOINT() };
	const auto index = static_cast<int>(sendMessage(RB_HITTEST, 0,
		reinterpret_cast<LPARAM>(&info)));
	if(flags) {
		*flags = info.flags;
	}
	return index;
}

bool Rebar::showBand(unsigned index, bool show) {
	return sendMessage(RB_SHOWBAND, index, show ? TRUE : FALSE) != FALSE;
}

void Rebar::maximizeBand(unsigned index, bool ideal) {
	sendMessage(RB_MAXIMIZEBAND, index, ideal ? TRUE : FALSE);
}

void Rebar::minimizeBand(unsigned index) {
	sendMessage(RB_MINIMIZEBAND, index);
}

bool Rebar::moveBand(unsigned from, unsigned to) {
	return sendMessage(RB_MOVEBAND, from, to) != FALSE;
}

}
