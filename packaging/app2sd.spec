Name:       app2sd
Summary:    Application installation on external memory
Version:    0.5.43
Release:    1
Group:      Application Framework/Package Management
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz

BuildRequires:  pkgconfig(libssl)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(db-util)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(minizip)
BuildRequires:  pkgconfig(libtzplatform-config)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(aul)
BuildRequires:  cmake

%if "%{?profile}" == "common"
%define tizen_feature_app2sd_plugin 1
%endif

%if "%{?profile}" == "mobile"
%define tizen_feature_app2sd_plugin 1
%endif

%if "%{?profile}" == "tv"
%define tizen_feature_app2sd_plugin 1
%endif

%description
Tizen application installation on external memory

%package devel
Summary:    Application install on external memory (devel)
Group:      Development/Libraries
Requires:   app2sd = %{version}-%{release}

%description devel
Tizen application installation on external memory (devel)

%package test
Summary:    Application install on external memory (test)
Group:      Development/Libraries
Requires:   app2sd = %{version}-%{release}

%description test
Tizen application installation on external memory (test)

%prep
%setup -q

%build
%if 0%{?tizen_feature_app2sd_plugin}
_APP2SD_PLUGIN=ON
%else
_APP2SD_PLUGIN=OFF
%endif

%cmake . -DUNITDIR=%{_unitdir} \
    -DTIZEN_FEATURE_APP2SD_PLUGIN:BOOL=${_APP2SD_PLUGIN}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%manifest app2sd.manifest
%defattr(-,root,root,-)
%{_libdir}/libapp2ext.so.*
%if 0%{?tizen_feature_app2sd_plugin}
%{_libdir}/libapp2sd.so*
%{_bindir}/app2sd-server
%{_unitdir}/app2sd-server.service
%{_datadir}/dbus-1/system-services/org.tizen.app2sd.service
%config %{_sysconfdir}/dbus-1/system.d/org.tizen.app2sd.conf
%endif
/usr/share/license/%{name}

%files devel
%defattr(-,root,root,-)
%{_includedir}/app2ext_interface.h
%{_libdir}/pkgconfig/app2sd.pc
%if 0%{?tizen_feature_app2sd_plugin}
%{_libdir}/libapp2sd.so
%endif
%{_libdir}/libapp2ext.so

%if 0%{?tizen_feature_app2sd_plugin}
%files test
%defattr(-,root,root,-)
%{_bindir}/test_app2ext
%endif
