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
      * Neither the name of the DWT nor SmartWin++ nor the names of its contributors
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

#include <dwt/Clipboard.h>

#include <dwt/util/check.h>
#include <dwt/widgets/Control.h>

#include <cstring>
#include <limits>

namespace dwt { namespace Clipboard {

void setData(const tstring& str, Control* w) {
	dwtassert(w, "Clipboard::setData: invalid widget");
	if(!w || !::IsWindow(w->handle())) {
		return;
	}

	const auto maxCharacters =
		(std::numeric_limits<SIZE_T>::max)() / sizeof(TCHAR);
	if(str.size() >= maxCharacters) {
		dwtWin32DebugFail("Clipboard::setData: text is too large");
		return;
	}

	const SIZE_T bytes = (str.size() + 1) * sizeof(TCHAR);
	auto handle = ::GlobalAlloc(GMEM_MOVEABLE, bytes);
	if(!handle) {
		dwtWin32DebugFail("Clipboard::setData: GlobalAlloc failed");
		return;
	}

	auto buf = reinterpret_cast<TCHAR*>(::GlobalLock(handle));
	if(!buf) {
		dwtWin32DebugFail("Clipboard::setData: GlobalLock failed");
		::GlobalFree(handle);
		return;
	}
	std::memcpy(buf, str.c_str(), bytes);
	::GlobalUnlock(handle);

	bool opened = false;
	for(unsigned attempt = 0; attempt < 5 && !opened; ++attempt) {
		opened = ::OpenClipboard(w->handle()) != FALSE;
		if(!opened && attempt + 1 < 5) {
			::Sleep(1);
		}
	}
	if(!opened) {
		dwtWin32DebugFail("Clipboard::setData: OpenClipboard failed");
		::GlobalFree(handle);
		return;
	}

	if(!::EmptyClipboard()) {
		dwtWin32DebugFail("Clipboard::setData: EmptyClipboard failed");
		::CloseClipboard();
		::GlobalFree(handle);
		return;
	}

#ifdef _UNICODE
	const auto format = CF_UNICODETEXT;
#else
	const auto format = CF_TEXT;
#endif

	if(!::SetClipboardData(format, handle)) {
		dwtWin32DebugFail("Clipboard::setData: SetClipboardData failed");
		::GlobalFree(handle);
	}
	// On success, ownership of handle has transferred to the clipboard.
	::CloseClipboard();
}

} }
