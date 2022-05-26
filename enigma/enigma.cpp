#include "enigma.h"

PYBIND11_MODULE(enigma, m)
{
	using namespace py;

	py::class_<Enigma>(m, "Enigma")
		.def_static("__new__", [](const object&) { return Enigma::instance(); },
			return_value_policy::reference_internal)
		.def_property_readonly_static("protected", [](const object&) -> bool { return EP_CheckupIsProtected(); })
		.def_property_readonly_static("integrated", [](const object&) -> bool { return EP_CheckupIsEnigmaOk(); })
		.def_property_readonly_static("hardware_id", [](const object&) { return EP_RegHardwareIDW(); })
		.def_readonly("registration", &Enigma::registration_)
		.def_readonly("trial", &Enigma::trial_);

	m.add_object("license", py::cast(Enigma::instance()));

	py::class_<Registration>(m, "Registration")
		.def_static("__new__", [](const object&) { return Registration::instance(); },
			return_value_policy::reference_internal)
		.def_readonly("name", &Registration::name_)
		.def_readonly("key", &Registration::key_)
		.def_readonly("key_info", &Registration::key_info_)
		.def("save_key", &Registration::SaveKey)
		.def_static("check_key", static_cast<bool(*)()>(&Registration::CheckKey))
		.def_static("check_key", static_cast<bool(*)(const wchar_t*, const wchar_t*)>(&Registration::CheckKey))
		.def_static("key_information", &Registration::KeyInformation);

	py::class_<TKeyInformation>(m, "KeyInformation")
		.def_readonly("stolen", &TKeyInformation::Stolen)
		.def_readonly("creation_year", &TKeyInformation::CreationYear)
		.def_readonly("creation_month", &TKeyInformation::CreationMonth)
		.def_readonly("creation_day", &TKeyInformation::CreationDay)
		.def_readonly("use_key_expiration", &TKeyInformation::UseKeyExpiration)
		.def_readonly("expiration_year", &TKeyInformation::ExpirationYear)
		.def_readonly("expiration_month", &TKeyInformation::ExpirationMonth)
		.def_readonly("expiration_day", &TKeyInformation::ExpirationDay)
		.def_readonly("use_hardware_locking", &TKeyInformation::UseHardwareLocking)
		.def_readonly("use_executions_limit", &TKeyInformation::UseExecutionsLimit)
		.def_readonly("executions_count", &TKeyInformation::ExecutionsCount)
		.def_readonly("use_days_limit", &TKeyInformation::UseDaysLimit)
		.def_readonly("days_count", &TKeyInformation::DaysCount)
		.def_readonly("use_run_time_limit", &TKeyInformation::UseRunTimeLimit)
		.def_readonly("run_time_minutes", &TKeyInformation::RunTimeMinutes)
		.def_readonly("use_global_time_limit", &TKeyInformation::UseGlobalTimeLimit)
		.def_readonly("global_time_minutes", &TKeyInformation::GlobalTimeMinutes)
		.def_readonly("use_county_limit", &TKeyInformation::UseCountyLimit)
		.def_readonly("country_code", &TKeyInformation::CountryCode)
		.def_readonly("use_register_after", &TKeyInformation::UseRegisterAfter)
		.def_readonly("register_after_year", &TKeyInformation::RegisterAfterYear)
		.def_readonly("use_county_limit", &TKeyInformation::UseCountyLimit)
		.def_readonly("register_after_month", &TKeyInformation::RegisterAfterMonth)
		.def_readonly("register_after_day", &TKeyInformation::RegisterAfterDay)
		.def_readonly("use_register_before", &TKeyInformation::UseRegisterBefore)
		.def_readonly("register_before_year", &TKeyInformation::RegisterBeforeYear)
		.def_readonly("register_before_month", &TKeyInformation::RegisterBeforeMonth)
		.def_readonly("register_before_day", &TKeyInformation::RegisterBeforeDay);

	py::enum_<Trial::TrialStatus>(m, "TrialStatus")
		.value("Expired", Trial::TrialStatus::kExpired)
		.value("Valid", Trial::TrialStatus::kValid)
		.value("Disabled", Trial::TrialStatus::kDisabled)
		.export_values();

	py::class_<Trial>(m, "Trial")
		.def_static("__new__", [](const object&) { return Trial::instance(); },
			return_value_policy::reference_internal)
		.def_readonly("executions_enabled", &Trial::executions_enabled_)
		.def_readonly("expiration_date", &Trial::expiration_date_)
		.def_readonly("executions_total", &Trial::executions_total_)
		.def_readonly("executions_left", &Trial::executions_left_)
		.def("check_trial", &Trial::CheckTrial);
}

Registration::Registration()
{
	LoadKey();
}

Trial::Trial()
{
	executions_enabled_ = EP_TrialExecutions(&executions_total_, &executions_left_);

	using namespace std::chrono;
	int days_total, days_left = 0;
	std::time_t expiration = 0;
	if (EP_TrialDays(&days_total, &days_left))
		expiration = system_clock::to_time_t(floor<days>(system_clock::now() + days{ days_left }));

	if (const int expiration_date = EP_TrialExpirationDateEx())
		expiration = max(expiration,
			system_clock::to_time_t(sys_days{ year(expiration_date & 0xFFFF) / month(expiration_date >> 16 & 0xFF) / day(expiration_date >> 24) }));
	expiration_date_ = expiration;
}

Trial::TrialStatus Trial::CheckTrial() const
{
	if (executions_enabled_ && executions_left_ < 0)
		return TrialStatus::kExpired;

	if (expiration_date_ == 0)
		return TrialStatus::kDisabled;

	using namespace std::chrono;
	return system_clock::to_time_t(system_clock::now()) > expiration_date_ ? TrialStatus::kExpired : TrialStatus::kValid;
}

bool Registration::LoadKey()
{
	wchar_t* name = nullptr;
	wchar_t* key = nullptr;
	if (EP_RegLoadKeyW(&name, &key) && EP_RegCheckKeyW(name, key))
	{
		name_ = std::wstring(name);
		key_ = std::wstring(key);
		return EP_RegKeyInformationW(name, key, &key_info_);
	}
	return false;
}

bool Registration::SaveKey(const wchar_t* name, const wchar_t* key)
{
	if(EP_RegCheckAndSaveKeyW(name, key))
	{
		name_ = std::wstring(name);
		key_ = std::wstring(key);
		return EP_RegKeyInformationW(name, key, &key_info_);
	}
	return false;
}

bool Registration::CheckKey()
{
	return EP_RegLoadAndCheckKey();
}

bool Registration::CheckKey(const wchar_t* name, const wchar_t* key)
{
	return EP_RegCheckKeyW(name, key);
}

std::tuple<bool, TKeyInformation> Registration::KeyInformation(const wchar_t* name, const wchar_t* key)
{
	TKeyInformation key_info{};
	return std::make_tuple(EP_RegKeyInformationW(name, key, &key_info), key_info);
}

Enigma::Enigma()
{
	registration_ = Registration::instance();
	trial_ = Trial::instance();
}
