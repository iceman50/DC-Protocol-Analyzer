/*
  DC++ Widget Toolkit

  Copyright (c) 2007-2026, Jacek Sieka

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
  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <dwt/widgets/MonthCalendar.h>

namespace dwt {

const TCHAR MonthCalendar::windowClass[] = MONTHCAL_CLASS;

MonthCalendar::Seed::Seed() :
	BaseType::Seed(WS_CHILD | WS_TABSTOP),
	font(0),
	backgroundColor(NaC),
	monthBackgroundColor(NaC),
	textColor(NaC),
	titleBackgroundColor(NaC),
	titleTextColor(NaC),
	trailingTextColor(NaC)
{
	::GetSystemTime(&initialDate);
}

void MonthCalendar::create(const Seed& cs) {
	ControlType::create(cs);
	setFont(cs.font);
	if(hasStyle(MCS_MULTISELECT)) {
		setSelectionRange(cs.initialDate, cs.initialDate);
	} else {
		setValue(cs.initialDate);
	}

	if(cs.backgroundColor != NaC) {
		setColor(MCSC_BACKGROUND, cs.backgroundColor);
	}
	if(cs.monthBackgroundColor != NaC) {
		setColor(MCSC_MONTHBK, cs.monthBackgroundColor);
	}
	if(cs.textColor != NaC) {
		setColor(MCSC_TEXT, cs.textColor);
	}
	if(cs.titleBackgroundColor != NaC) {
		setColor(MCSC_TITLEBK, cs.titleBackgroundColor);
	}
	if(cs.titleTextColor != NaC) {
		setColor(MCSC_TITLETEXT, cs.titleTextColor);
	}
	if(cs.trailingTextColor != NaC) {
		setColor(MCSC_TRAILINGTEXT, cs.trailingTextColor);
	}
}

Point MonthCalendar::getPreferredSize() {
	auto rect = getMinRequiredRect();
	if(rect.width() > 0 && rect.height() > 0) {
		return rect.size;
	}
	return scale(Point(180, 160));
}

}
