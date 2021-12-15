import PySimpleGUI as sg
import datetime
import main



file_list = [
    [
        sg.Text("Выбор файла с правилами:"),
        sg.In(size=(25,1), enable_events=True, key='-FILE-', change_submits=True, visible=False),
        sg.FileBrowse(key='-IN FILE-', file_types=("Text Files", "*.txt")),
        sg.Button(button_text="Запуск", key="-START-")
    ],
    [sg.In(size=(52,20), enable_events=True, key='-FILE2-', change_submits=True),
    ],
    [
        sg.MLine(enable_events=True, size=(50,10),
            key ="-FILE READER-",
        )
    ],
]

file_viewer = [
    [sg.Text("Журнал обнаружения вторжений:")],
    [sg.Text(size=(40,1), key="-TOUT-")],
    [sg.MLine(key="-OUTPUT-", size=(60, 40)),],
]


layout = [
    [
        sg.Column(file_list),
        #sg.Column(file_viewer),
        sg.VSeparator(),
        sg.Column(file_viewer)
    ]
]

window = sg.Window("Система обнаружения вторжений", layout, resizable=True)
start = False

while True:
    event, values = window.read()
    if event == "Выход" or event == sg.WIN_CLOSED:
        break
    if event == "-START-":
        start = True
        file = open(values["-IN FILE-"], 'r')
        file2 = open(values["-IN FILE-"], 'r')
        window["-FILE READER-"].Update(file.read())
        now = datetime.datetime.today()
        output = str(now) + ".log"
        main.main(file2.read(), output)
        window["-FILE-"].Update("")
        window["-FILE2-"].Update(values["-IN FILE-"])
        sg.Popup('СОВ запущена', keep_on_top=True)
    if start:
        file_w = open(output, 'r').read()
        window["-OUTPUT-"].Update(file_w)
window.close()