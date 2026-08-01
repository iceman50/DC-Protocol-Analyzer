# Canonical MinGW-w64 x64 build for Protocol Analyzer.
#
# Release packaging is performed by ../../build_dist.ps1. This Makefile only
# produces the DLL and its GNU debug companion; it never mutates source files.

TARGET_NAME := ProtocolAnalyzer

PREFIX ?= x86_64-w64-mingw32-
CC = $(PREFIX)gcc
CXX = $(PREFIX)g++
WINDRES = $(shell "$(CC)" -print-prog-name=windres)
OBJCOPY = $(shell "$(CC)" -print-prog-name=objcopy)
POWERSHELL ?= powershell

CONFIG ?= Release
VALID_CONFIG := $(filter $(CONFIG),Debug Release)
ifneq ($(words $(CONFIG)),1)
$(error CONFIG must be exactly one of Debug or Release)
endif
ifeq ($(VALID_CONFIG),)
$(error CONFIG must be exactly one of Debug or Release)
endif

COMPILER_SPEC := $(strip $(shell "$(CC)" -dumpmachine))
CXX_COMPILER_SPEC := $(strip $(shell "$(CXX)" -dumpmachine))
ifeq ($(findstring x86_64,$(COMPILER_SPEC)),)
$(error CC must target x86_64 MinGW-w64; got '$(COMPILER_SPEC)')
endif
ifeq ($(findstring mingw32,$(COMPILER_SPEC)),)
$(error CC must target x86_64 MinGW-w64; got '$(COMPILER_SPEC)')
endif
ifneq ($(COMPILER_SPEC),$(CXX_COMPILER_SPEC))
$(error CC and CXX target different platforms: '$(COMPILER_SPEC)' vs '$(CXX_COMPILER_SPEC)')
endif

ROOT := ../..
ROOT_ABS := $(abspath $(ROOT))
NORMALIZE_PE_TIMESTAMP := $(ROOT)/scripts/normalize_pe_timestamp.ps1
OUTPUT_DIR := build-mingw-x64
ifeq ($(CONFIG),Debug)
OUTPUT_DIR := $(OUTPUT_DIR)-debug
endif

TARGET := $(OUTPUT_DIR)/$(TARGET_NAME).dll
UNSTRIPPED_TARGET := $(OUTPUT_DIR)/$(TARGET_NAME).unstripped.dll
DEBUG_FILE := $(OUTPUT_DIR)/$(TARGET_NAME).dbg

COMMON_DEFINES := \
	-D_WIN32_WINNT=0x0601 \
	-DWINVER=0x0601 \
	-D_WIN32_IE=0x0A00 \
	-DNOMINMAX \
	-DSTRICT \
	-DWIN32_LEAN_AND_MEAN \
	-DWIN32 \
	-D_WIN32 \
	-DUNICODE \
	-D_UNICODE \
	-DDWT_SHARED

CPPFLAGS += -I$(ROOT) -I$(ROOT)/dwt/include $(COMMON_DEFINES)
CXXFLAGS += \
	-std=gnu++17 \
	-Wall \
	-Wextra \
	-Wformat=2 \
	-Wformat-security \
	-Wno-unknown-pragmas \
	-Wno-missing-field-initializers \
	-Wno-unused-parameter \
	-pipe \
	-fstack-protector-strong \
	-ffile-prefix-map=$(ROOT_ABS)=. \
	-fdebug-prefix-map=$(ROOT_ABS)=. \
	-fmacro-prefix-map=$(ROOT_ABS)=.

ifeq ($(CONFIG),Debug)
CPPFLAGS += -D_DEBUG
CXXFLAGS += -O0 -g3 -fno-omit-frame-pointer
RC_CONFIG_FLAGS := -D_DEBUG
else
CPPFLAGS += -DNDEBUG -D_FORTIFY_SOURCE=2
CXXFLAGS += -O3 -g
RC_CONFIG_FLAGS := -DNDEBUG
endif

LDFLAGS += \
	-shared \
	-static-libgcc \
	-static-libstdc++ \
	-Wl,--add-stdcall-alias \
	-Wl,--dynamicbase \
	-Wl,--nxcompat \
	-Wl,--high-entropy-va \
	-Wl,--major-subsystem-version,6,--minor-subsystem-version,1 \
	-Wl,--no-insert-timestamp

LDLIBS += \
	-lcomctl32 \
	-lcomdlg32 \
	-lgdi32 \
	-lole32 \
	-loleaut32 \
	-lshlwapi \
	-luuid \
	-lshell32 \
	-ladvapi32 \
	-luxtheme \
	-ldwmapi \
	-lbcrypt

RCFLAGS := \
	--target=pe-x86-64 \
	-D_WIN32_WINNT=0x0601 \
	-DWINVER=0x0601 \
	-D_WIN32_IE=0x0A00 \
	-DUNICODE \
	-D_UNICODE \
	$(RC_CONFIG_FLAGS)

OBJS := \
	pluginsdk/Config.o \
	pluginsdk/Connections.o \
	pluginsdk/Core.o \
	pluginsdk/DataAccess.o \
	pluginsdk/Hooks.o \
	pluginsdk/Hubs.o \
	pluginsdk/Logger.o \
	pluginsdk/Queue.o \
	pluginsdk/Tagger.o \
	pluginsdk/UI.o \
	pluginsdk/Util.o \
	src/CustomTitleBar.o \
	src/GUI.o \
	src/main.o \
	src/Plugin.o \
	src/ProtocolAnalyzer.o \
	src/SettingsDlg.o \
	src/stdafx.o \
	src/resource.o \
	dwt/src/Application.o \
	dwt/src/Bitmap.o \
	dwt/src/Brush.o \
	dwt/src/CanvasClasses.o \
	dwt/src/Clipboard.o \
	dwt/src/CommandLine.o \
	dwt/src/Dispatcher.o \
	dwt/src/DWTException.o \
	dwt/src/Events.o \
	dwt/src/Font.o \
	dwt/src/Icon.o \
	dwt/src/ImageList.o \
	dwt/src/LibraryLoader.o \
	dwt/src/Message.o \
	dwt/src/Pen.o \
	dwt/src/Point.o \
	dwt/src/Rectangle.o \
	dwt/src/Region.o \
	dwt/src/Taskbar.o \
	dwt/src/Texts.o \
	dwt/src/Theme.o \
	dwt/src/Widget.o \
	dwt/src/util/DateTimeUtil.o \
	dwt/src/util/GDI.o \
	dwt/src/util/RegKey.o \
	dwt/src/util/StringUtils.o \
	dwt/src/util/TimeSpan.o \
	dwt/src/util/win32/AccessibilityProvider.o \
	dwt/src/util/win32/ApiHelpers.o \
	dwt/src/util/win32/Dpi.o \
	dwt/src/util/win32/FileDialog.o \
	dwt/src/util/win32/Version.o \
	dwt/src/widgets/Button.o \
	dwt/src/widgets/CheckBox.o \
	dwt/src/widgets/ColorDialog.o \
	dwt/src/widgets/ComboBox.o \
	dwt/src/widgets/Control.o \
	dwt/src/widgets/DateTime.o \
	dwt/src/widgets/FolderDialog.o \
	dwt/src/widgets/FontDialog.o \
	dwt/src/widgets/Grid.o \
	dwt/src/widgets/GroupBox.o \
	dwt/src/widgets/Header.o \
	dwt/src/widgets/Label.o \
	dwt/src/widgets/Link.o \
	dwt/src/widgets/LoadDialog.o \
	dwt/src/widgets/MDIChild.o \
	dwt/src/widgets/MDIFrame.o \
	dwt/src/widgets/MDIParent.o \
	dwt/src/widgets/Menu.o \
	dwt/src/widgets/MessageBox.o \
	dwt/src/widgets/ModalDialog.o \
	dwt/src/widgets/ModelessDialog.o \
	dwt/src/widgets/MonthCalendar.o \
	dwt/src/widgets/Notification.o \
	dwt/src/widgets/ProgressBar.o \
	dwt/src/widgets/RadioButton.o \
	dwt/src/widgets/Rebar.o \
	dwt/src/widgets/RichTextBox.o \
	dwt/src/widgets/SaveDialog.o \
	dwt/src/widgets/ScrolledContainer.o \
	dwt/src/widgets/Slider.o \
	dwt/src/widgets/Spinner.o \
	dwt/src/widgets/Splitter.o \
	dwt/src/widgets/SplitterContainer.o \
	dwt/src/widgets/StatusBar.o \
	dwt/src/widgets/Table.o \
	dwt/src/widgets/TableTree.o \
	dwt/src/widgets/TabView.o \
	dwt/src/widgets/TaskDialog.o \
	dwt/src/widgets/TextBox.o \
	dwt/src/widgets/ToolBar.o \
	dwt/src/widgets/ToolTip.o \
	dwt/src/widgets/Tree.o \
	dwt/src/widgets/VirtualTree.o \
	dwt/src/widgets/Window.o

CPP_OBJECTS := $(filter-out src/resource.o,$(OBJS))
CPP_SOURCES := $(addprefix $(ROOT)/,$(CPP_OBJECTS:.o=.cpp))
OBJS := $(addprefix $(OUTPUT_DIR)/,$(OBJS))
DEPS := $(filter %.o,$(OBJS))
DEPS := $(DEPS:.o=.d)

ANALYZER_FLAGS := -fanalyzer -fsyntax-only -Werror
PROTOCOL_ANALYZER_TEST := $(OUTPUT_DIR)/protocol_analyzer_tests.exe
PROTOCOL_ANALYZER_TEST_FLAGS := \
	-Wpedantic \
	-Werror \
	-Wconversion \
	-Wsign-conversion

ifeq ($(OS),Windows_NT)
define MAKE_DIRECTORY
	if not exist "$(subst /,\,$1)" mkdir "$(subst /,\,$1)"
endef
define REMOVE_DIRECTORY
	if exist "$(subst /,\,$1)" rmdir /s /q "$(subst /,\,$1)"
endef
define MOVE_FILE
	move /Y "$(subst /,\,$1)" "$(subst /,\,$2)" >NUL
endef
else
define MAKE_DIRECTORY
	mkdir -p "$1"
endef
define REMOVE_DIRECTORY
	rm -rf -- "$1"
endef
define MOVE_FILE
	mv -f -- "$1" "$2"
endef
endif

.DELETE_ON_ERROR:
.PHONY: all clean print-config source-audit protocol-analyzer-test

all: $(TARGET) $(DEBUG_FILE)

source-audit:
	@echo Running GCC static analysis over every plugin, SDK, and DWT translation unit...
	"$(CXX)" $(CPPFLAGS) $(CXXFLAGS) $(ANALYZER_FLAGS) $(CPP_SOURCES)

protocol-analyzer-test: $(PROTOCOL_ANALYZER_TEST)
	"$(PROTOCOL_ANALYZER_TEST)"

print-config:
	@echo CONFIG=$(CONFIG)
	@echo CC=$(CC)
	@echo CXX=$(CXX)
	@echo WINDRES=$(WINDRES)
	@echo OBJCOPY=$(OBJCOPY)
	@echo COMPILER_SPEC=$(COMPILER_SPEC)
	@echo OUTPUT_DIR=$(OUTPUT_DIR)
	@echo TARGET=$(TARGET)
	@echo DEBUG_FILE=$(DEBUG_FILE)

$(UNSTRIPPED_TARGET): $(OBJS)
	"$(CXX)" $(OBJS) $(LDFLAGS) $(LDLIBS) -o "$@.tmp" && $(call MOVE_FILE,$@.tmp,$@)

$(DEBUG_FILE): $(UNSTRIPPED_TARGET)
	"$(OBJCOPY)" --only-keep-debug "$<" "$@.tmp" && \
		"$(POWERSHELL)" -NoProfile -ExecutionPolicy Bypass \
		-File "$(NORMALIZE_PE_TIMESTAMP)" -Path "$@.tmp" && \
		$(call MOVE_FILE,$@.tmp,$@)

$(TARGET): $(UNSTRIPPED_TARGET) $(DEBUG_FILE)
	"$(OBJCOPY)" --strip-unneeded --add-gnu-debuglink="$(abspath $(DEBUG_FILE))" "$<" "$@.tmp" && \
		"$(POWERSHELL)" -NoProfile -ExecutionPolicy Bypass \
		-File "$(NORMALIZE_PE_TIMESTAMP)" -Path "$@.tmp" && \
		$(call MOVE_FILE,$@.tmp,$@)

$(PROTOCOL_ANALYZER_TEST): \
	$(ROOT)/tests/protocol_analyzer_tests.cpp \
	$(ROOT)/src/ProtocolAnalyzer.cpp \
	$(ROOT)/src/ProtocolAnalyzer.h \
	Makefile | $(OUTPUT_DIR)
	"$(CXX)" $(CPPFLAGS) $(CXXFLAGS) $(PROTOCOL_ANALYZER_TEST_FLAGS) \
		-frandom-seed="protocol-analyzer-test-$(CONFIG)" \
		"$(ROOT)/tests/protocol_analyzer_tests.cpp" \
		"$(ROOT)/src/ProtocolAnalyzer.cpp" \
		-static-libgcc -static-libstdc++ \
		-Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va \
		-Wl,--no-insert-timestamp \
		-o "$@.tmp" && $(call MOVE_FILE,$@.tmp,$@)

$(OUTPUT_DIR)/%.o: $(ROOT)/%.cpp Makefile
	"$(CXX)" $(CPPFLAGS) $(CXXFLAGS) -frandom-seed="$@" -MMD -MP -MF "$(@:.o=.d)" -c "$<" -o "$@"

$(OUTPUT_DIR)/src/resource.o: $(ROOT)/src/resource.rc $(ROOT)/src/resource.h Makefile
	"$(WINDRES)" $(RCFLAGS) -i "$<" -o "$@"

$(OBJS): | $(OUTPUT_DIR)

$(OUTPUT_DIR):
	$(call MAKE_DIRECTORY,$(OUTPUT_DIR)/pluginsdk)
	$(call MAKE_DIRECTORY,$(OUTPUT_DIR)/src)
	$(call MAKE_DIRECTORY,$(OUTPUT_DIR)/dwt/src)
	$(call MAKE_DIRECTORY,$(OUTPUT_DIR)/dwt/src/util)
	$(call MAKE_DIRECTORY,$(OUTPUT_DIR)/dwt/src/util/win32)
	$(call MAKE_DIRECTORY,$(OUTPUT_DIR)/dwt/src/widgets)

clean:
	$(call REMOVE_DIRECTORY,$(OUTPUT_DIR))

-include $(DEPS)
