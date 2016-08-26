Name:       libuser
Summary:    A user and group account administration library
Version:    0.62
Release:    1
Group:      System/Base
License:    LGPLv2+
URL:        https://fedorahosted.org/libuser/
Source0:    https://fedorahosted.org/releases/l/i/libuser/%{name}-%{version}.tar.xz
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(popt)
BuildRequires:  pam-devel
BuildRequires:  gettext-devel
BuildRequires:  python-devel
BuildRequires:  cvs

%description
%{summary}.

%package python
Summary:    Python bindings for the libuser library
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description python
%{summary}.

%package devel
Summary:    Files needed for developing applications which use libuser
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
%{summary}.

%prep
%setup -q -n %{name}-%{version}/%{name}

%build
%reconfigure --disable-static \
    --with-python \
    --disable-gtk-doc

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

%find_lang libuser

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files -f libuser.lang
%defattr(-,root,root,-)
%doc AUTHORS COPYING NEWS README TODO
%config(noreplace) %{_sysconfdir}/libuser.conf
%attr(0755,root,root) %{_bindir}/*
%{_libdir}/*.so.*
%dir %{_libdir}/%{name}
%{_libdir}/%{name}/*.so
%attr(0755,root,root) %{_sbindir}/*
%doc %{_mandir}/man1/*
%doc %{_mandir}/man5/*

%files python
%defattr(-,root,root,-)
%doc python/modules.txt
%{python_sitearch}/*.so

%files devel
%defattr(-,root,root,-)
%{_includedir}/libuser
%{_libdir}/*.so
%{_libdir}/pkgconfig/*
%{_datadir}/gtk-doc/html/libuser/*

