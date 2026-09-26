from io import BytesIO

import xlwt

from .member_reports import age_on


HEADERS = (
    "Member ID",
    "Name",
    "Account Role",
    "Gender",
    "Life Status",
    "Record Status",
    "Date of Birth",
    "Age",
    "Residence",
    "Phone Number",
    "Email",
)


def build_member_list_workbook(members):
    workbook = xlwt.Workbook(encoding="utf-8")
    sheet = workbook.add_sheet("Members")
    sheet.set_panes_frozen(True)
    sheet.set_horz_split_pos(1)

    header_style = xlwt.easyxf(
        "font: bold on, colour white; pattern: pattern solid, fore_colour ocean_blue; align: vert centre;"
    )
    date_style = xlwt.easyxf(num_format_str="DD MMM YYYY")
    for column, heading in enumerate(HEADERS):
        sheet.write(0, column, heading, header_style)

    for row, member in enumerate(members, start=1):
        values = (
            member.member_id,
            member.full_name,
            member.account.get_role_display() if member.account else "Clan record only",
            member.get_gender_display() or "Not recorded",
            "Living" if member.is_living else "Deceased",
            member.get_status_display(),
            member.date_of_birth,
            age_on(member.date_of_birth),
            member.current_residence or "Not recorded",
            member.phone_number,
            member.email,
        )
        for column, value in enumerate(values):
            if column == 6 and value:
                sheet.write(row, column, value, date_style)
            else:
                sheet.write(row, column, "" if value is None else value)

    widths = (20, 30, 20, 14, 14, 18, 16, 8, 26, 20, 28)
    for column, width in enumerate(widths):
        sheet.col(column).width = width * 256

    output = BytesIO()
    workbook.save(output)
    output.seek(0)
    return output
