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

#include <dwt/widgets/ComboBox.h>

#include <dwt/WidgetCreator.h>
#include <dwt/widgets/TextBox.h>

#include <vector>

namespace dwt {

const TCHAR ComboBox::windowClass[] = WC_COMBOBOX;

const TCHAR ComboBox::DropListBox::windowClass[] = _T("ComboLBox"); // undocumented

ComboBox::Seed::Seed() :
BaseType::Seed(CBS_DROPDOWN | CBS_AUTOHSCROLL | WS_CHILD | WS_TABSTOP | WS_VSCROLL),
font(0),
extended(true)
{
}

ComboBox::ComboBox(Widget* parent) :
	BaseType(parent, ChainingDispatcher::superClass<ComboBox>()),
	listBox(nullptr),
	textBox(nullptr)
{
}

void ComboBox::create( const Seed & cs ) {
	BaseType::create(cs);
	setFont(cs.font);
	if(cs.extended)
		sendMessage(CB_SETEXTENDEDUI, TRUE);
}

tstring ComboBox::getValue( int index ) {
	// Uses CB_GETLBTEXTLEN and CB_GETLBTEXT
	if(index < 0 || static_cast<size_t>(index) >= size()) {
		return tstring();
	}
	const int txtLength = ComboBox_GetLBTextLen(handle(), index);
	if(txtLength == CB_ERR || txtLength < 0) {
		return tstring();
	}
	std::vector<TCHAR> buffer(static_cast<size_t>(txtLength) + 1, _T('\0'));
	if(ComboBox_GetLBText(handle(), index, buffer.data()) == CB_ERR) {
		return tstring();
	}
	return tstring(buffer.data(), static_cast<size_t>(txtLength));
}

int ComboBox::findString(const tstring& text) {
	return ComboBox_FindStringExact(handle(), -1, text.c_str()); 
}

ComboBox::DropListBoxPtr ComboBox::getListBox() {
	if(!listBox) {
		COMBOBOXINFO info = { sizeof(COMBOBOXINFO) };
		if(::GetComboBoxInfo(handle(), &info) && info.hwndList && info.hwndList != handle()) {
			/* unlike other controls, the list window doesn't send/receive WM_DESTROY/WN_NCDESTROY.
			as a result, the listBox widget leaks. the workaround is to "detach" from the list (by
			giving it back its initial window procedure) when the combo is being destroyed. */
			auto proc = ::GetWindowLongPtr(info.hwndList, GWLP_WNDPROC);
			listBox = WidgetCreator<DropListBox>::attach(this, info.hwndList);
			listBox->onDestroy([this] { listBox = nullptr; });
			onDestroy([this, proc] { if(listBox) { ::SetWindowLongPtr(listBox->handle(), GWLP_WNDPROC, proc); listBox->kill(); } });
		}
	}
	return listBox;
}

TextBoxPtr ComboBox::getTextBox() {
	if(!textBox) {
		COMBOBOXINFO info = { sizeof(COMBOBOXINFO) };
		if(::GetComboBoxInfo(handle(), &info) && info.hwndItem && info.hwndItem != handle()) {
			/* combo edits do receive destruction messages, but we do the same crap as for lists
			to be on the safe side. */
			auto proc = ::GetWindowLongPtr(info.hwndItem, GWLP_WNDPROC);
			textBox = WidgetCreator<TextBox>::attach(this, info.hwndItem);
			textBox->onDestroy([this] { textBox = nullptr; });
			onDestroy([this, proc] { if(textBox) { ::SetWindowLongPtr(textBox->handle(), GWLP_WNDPROC, proc); textBox->kill(); } });
		}
	}
	return textBox;
}

void ComboBox::showDropDown(bool show) {
	sendMessage(CB_SHOWDROPDOWN, show ? TRUE : FALSE);
}

bool ComboBox::isDroppedDown() const {
	return sendMessage(CB_GETDROPPEDSTATE) != FALSE;
}

int ComboBox::getDroppedWidth() const {
	return static_cast<int>(sendMessage(CB_GETDROPPEDWIDTH));
}

int ComboBox::setDroppedWidth(int width) {
	return static_cast<int>(sendMessage(CB_SETDROPPEDWIDTH, width));
}

Rectangle ComboBox::getDroppedRect() const {
	RECT rectangle = { 0 };
	return sendMessage(CB_GETDROPPEDCONTROLRECT, 0,
		reinterpret_cast<LPARAM>(&rectangle)) ? Rectangle(rectangle) : Rectangle();
}

int ComboBox::getTopIndex() const {
	return static_cast<int>(sendMessage(CB_GETTOPINDEX));
}

bool ComboBox::setTopIndex(int index) {
	return sendMessage(CB_SETTOPINDEX, index) != CB_ERR;
}

int ComboBox::getHorizontalExtent() const {
	return static_cast<int>(sendMessage(CB_GETHORIZONTALEXTENT));
}

void ComboBox::setHorizontalExtent(int width) {
	sendMessage(CB_SETHORIZONTALEXTENT, width);
}

int ComboBox::getItemHeight(int index) const {
	return static_cast<int>(sendMessage(CB_GETITEMHEIGHT, index));
}

bool ComboBox::setItemHeight(int height, int index) {
	return sendMessage(CB_SETITEMHEIGHT, index, height) != CB_ERR;
}

std::pair<int, int> ComboBox::getEditSelection() const {
	DWORD start = 0;
	DWORD end = 0;
	if(sendMessage(CB_GETEDITSEL, reinterpret_cast<WPARAM>(&start),
		reinterpret_cast<LPARAM>(&end)) == CB_ERR)
	{
		return std::make_pair(-1, -1);
	}
	return std::make_pair(static_cast<int>(start), static_cast<int>(end));
}

bool ComboBox::setEditSelection(int start, int end) {
	return sendMessage(CB_SETEDITSEL, 0, MAKELPARAM(start, end)) != CB_ERR;
}

LCID ComboBox::getLocale() const {
	return static_cast<LCID>(sendMessage(CB_GETLOCALE));
}

LCID ComboBox::setLocale(LCID locale) {
	return static_cast<LCID>(sendMessage(CB_SETLOCALE, locale));
}

int ComboBox::getMinimumVisibleItems() const {
	return static_cast<int>(sendMessage(CB_GETMINVISIBLE));
}

bool ComboBox::setMinimumVisibleItems(int count) {
	return sendMessage(CB_SETMINVISIBLE, count) != FALSE;
}

bool ComboBox::getExtendedUI() const {
	return sendMessage(CB_GETEXTENDEDUI) != FALSE;
}

bool ComboBox::setExtendedUI(bool extended) {
	return sendMessage(CB_SETEXTENDEDUI, extended ? TRUE : FALSE) != CB_ERR;
}

COMBOBOXINFO ComboBox::getInfo() const {
	COMBOBOXINFO info = { sizeof(COMBOBOXINFO) };
	::GetComboBoxInfo(handle(), &info);
	return info;
}

Point ComboBox::getPreferredSize() {
	UpdateCanvas c(this);
	auto select(c.select(*getFont()));
	Point ret;
	for(size_t i = 0; i < size(); ++i) {
		Point ext = c.getTextExtent(getValue(static_cast<int>(i)));
		ret.x = std::max(ret.x, ext.x);
	}

	ret.x += getSystemMetric(SM_CXFIXEDFRAME) * 2 +
		getSystemMetric(SM_CXVSCROLL) + scale(2);
	const auto itemHeight = sendMessage(
		CB_GETITEMHEIGHT, static_cast<WPARAM>(-1), 0);
	ret.y = itemHeight == CB_ERR ? c.getTextExtent(_T("Mg")).y :
		static_cast<long>(itemHeight);
	ret.y += getSystemMetric(SM_CYFIXEDFRAME) * 2;
	return ret;
}

LPARAM ComboBox::getDataImpl(int i) {
	return sendMessage(CB_GETITEMDATA, i);
}

void ComboBox::setDataImpl(int i, LPARAM data) {
	sendMessage(CB_SETITEMDATA, i, data);
}

}
