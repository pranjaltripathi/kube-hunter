class CveUtils:
    @staticmethod
    def get_legacy_version_cls():
        return getattr(version, "LegacyVersion", None)

    @staticmethod
    def is_legacy_version(v):
        legacy_version_cls = CveUtils.get_legacy_version_cls()
        return legacy_version_cls is not None and isinstance(v, legacy_version_cls)

    @staticmethod
    def get_base_release(full_ver):
        # if LegacyVersion exists, converting manually to a base version
        if CveUtils.is_legacy_version(full_ver):
            return version.parse(".".join(full_ver._version.split(".")[:2]))
        return version.parse(".".join(map(str, full_ver._version.release[:2])))

    @staticmethod
    def to_legacy(full_ver):
        # converting version to LegacyVersion when available
        raw_version = ".".join(map(str, full_ver._version.release))
        legacy_version_cls = CveUtils.get_legacy_version_cls()
        if legacy_version_cls is not None:
            return legacy_version_cls(raw_version)
        return version.parse(raw_version)

    @staticmethod
    def to_raw_version(v):
        if not CveUtils.is_legacy_version(v):
            return ".".join(map(str, v._version.release))
        return v._version

    @staticmethod
    def version_compare(v1, v2):
        """Function compares two versions, handling differences with conversion to LegacyVersion"""
        # getting raw version, while striping 'v' char at the start. if exists.
        # removing this char lets us safely compare the two version.
        v1_raw = CveUtils.to_raw_version(v1).strip("v")
        v2_raw = CveUtils.to_raw_version(v2).strip("v")

        legacy_version_cls = CveUtils.get_legacy_version_cls()
        if legacy_version_cls is not None:
            new_v1 = legacy_version_cls(v1_raw)
            new_v2 = legacy_version_cls(v2_raw)
        else:
            new_v1 = version.parse(v1_raw)
            new_v2 = version.parse(v2_raw)

        return CveUtils.basic_compare(new_v1, new_v2)

    @staticmethod
    def basic_compare(v1, v2):
        return (v1 > v2) - (v1 < v2)

    @staticmethod
    def is_downstream_version(version):
        return any(c in version for c in "+-~")

    @staticmethod
    def is_vulnerable(fix_versions, check_version, ignore_downstream=False):
        """Function determines if a version is vulnerable,
        by comparing to given fix versions by base release"""
        if ignore_downstream and CveUtils.is_downstream_version(check_version):
            return False

        vulnerable = False
        check_v = version.parse(check_version)
        base_check_v = CveUtils.get_base_release(check_v)

        # default to classic compare, unless the check_version is legacy.
        version_compare_func = CveUtils.basic_compare
        if CveUtils.is_legacy_version(check_v):
            version_compare_func = CveUtils.version_compare

        if check_version not in fix_versions:
            # comparing ease base release for a fix
            for fix_v in fix_versions:
                fix_v = version.parse(fix_v)
                base_fix_v = CveUtils.get_base_release(fix_v)

                # if the check version and the current fix has the same base release
                if base_check_v == base_fix_v:
                    # when check_version is legacy, we use a custom compare func, to handle differences between versions
                    if version_compare_func(check_v, fix_v) == -1:
                        # determine vulnerable if smaller and with same base version
                        vulnerable = True
                        break

        # if we did't find a fix in the fix releases, checking if the version is smaller that the first fix
        if not vulnerable and version_compare_func(check_v, version.parse(fix_versions[0])) == -1:
            vulnerable = True

        return vulnerable

