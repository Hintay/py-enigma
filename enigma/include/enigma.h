#pragma once

#include <pybind11/pybind11.h>
#include <string>
#include <chrono>

#include "enigma_ide.h"

namespace py = pybind11;

class Trial
{
public:
	explicit Trial();
	static auto& instance() {
		static Trial instance;
		return instance;
	}

	enum class TrialStatus
	{
		kExpired,
		kValid,
		kDisabled
	};

	[[nodiscard]] TrialStatus CheckTrial() const;

	std::time_t expiration_date_;
	bool executions_enabled_;
	int executions_total_ = 0;
	int executions_left_ = 0;
};


class Registration
{
public:
	explicit Registration();
	static auto& instance() {
		static Registration instance;
		return instance;
	}

	bool LoadKey();
	bool SaveKey(const wchar_t* name, const wchar_t* key);
	bool DeleteKey();

	static bool CheckKey();
	static bool CheckKey(const wchar_t* name, const wchar_t* key);
	static std::tuple<bool, TKeyInformation> KeyInformation(const wchar_t* name, const wchar_t* key);

	std::wstring name_;
	std::wstring key_;
	TKeyInformation key_info_{};
};


class Enigma
{
public:
	static auto& instance() {
		static Enigma instance;
		return instance;
	}

	Registration registration_;
	Trial trial_;

private:
	explicit Enigma();
};