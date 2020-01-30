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

%description
%{summary}.

%package devel
Summary:    Files needed for developing applications which use libuser
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
%{summary}.

%package doc
Summary:   Documentation for %{name}
Group:     Documentation
Requires:  %{name} = %{version}-%{release}

%description doc
Man pages for %{name}.

%prep
%setup -q -n %{name}-%{version}/%{name}

%build
%reconfigure --disable-static \
    --without-python \
    --disable-gtk-doc

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

%find_lang libuser

mkdir -p %{buildroot}%{_docdir}/%{name}-%{version}
install -m0644 -t %{buildroot}%{_docdir}/%{name}-%{version} \
	AUTHORS NEWS README TODO

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files -f libuser.lang
%defattr(-,root,root,-)
%license COPYING
%config %{_sysconfdir}/libuser.conf
%attr(0755,root,root) %{_bindir}/*
%{_libdir}/*.so.*
%dir %{_libdir}/%{name}
%{_libdir}/%{name}/*.so
%attr(0755,root,root) %{_sbindir}/*

%files devel
%defattr(-,root,root,-)
%{_includedir}/libuser
%{_libdir}/*.so
%{_libdir}/pkgconfig/*

%files doc
%defattr(-,root,root,-)
%{_mandir}/man1/*
%{_mandir}/man5/%{name}.*
%{_docdir}/%{name}-%{version}
%doc %{_datadir}/gtk-doc/html/libuser/*
