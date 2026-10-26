package io.github.runsecure.hkdfguard.securefile;

/** What GetDriveTypeW reports for a drive root, by its DRIVE_* value, named as .NET's DriveType names it. */
enum DriveType {
    UNKNOWN("Unknown"),
    NO_ROOT_DIRECTORY("NoRootDirectory"),
    REMOVABLE("Removable"),
    FIXED("Fixed"),
    NETWORK("Network"),
    CD_ROM("CDRom"),
    RAM("Ram");

    private final String displayName;

    DriveType(String displayName) {
        this.displayName = displayName;
    }

    /** The type GetDriveTypeW's return value names; anything it doesn't define is {@link #UNKNOWN}. */
    static DriveType fromWin32(int value) {
        var values = values();
        return value >= 0 && value < values.length ? values[value] : UNKNOWN;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
