# coding: utf-8
# Copyright 2017

"""Implementing the graphical interface."""

from glob import glob
from os import path
from typing import Dict, List

from kivy.app import App
from kivy.core.window import Window
from kivy.factory import Factory
from kivy.lang import Builder
from kivy.uix.image import Image
from kivy.uix.vkeyboard import VKeyboard
from widgetskv import WKV_ABOUT_DIALOG, WKV_PANEL_MENU, WKV_SEPARATOR_LINE

from .checker import Checker


class Gui(App):

    """Class of the main window and runing of the application."""

    checker: Checker = Checker()
    title: str = "Password checker"
    version: str = "0.1.0"
    create_year: int = 2017
    license_link: str = "https://www.gnu.org/licenses/gpl-3.0"
    project_link: str = "https://github.com/Paduct/password_checker"
    description: str = checker.DESCRIPTION

    VIRTUAL_KEYBOARD: VKeyboard = VKeyboard()
    POSITIVE_ICON: str = "atlas://data/images/defaulttheme/checkbox_on"
    NEGATIVE_ICON: str = "atlas://data/images/defaulttheme/image-missing"

    def build(self):
        """Accumulate of resources and the start of the main window."""
        project_path: str = path.split(path.dirname(__file__))[0]
        kv_files_path: str = path.join(project_path, "uix", "*.kv")
        kv_file_names: List[str] = glob(kv_files_path)
        kv_file_names.extend(
            (WKV_PANEL_MENU, WKV_SEPARATOR_LINE, WKV_ABOUT_DIALOG)
        )

        for file_name in kv_file_names:
            Builder.load_file(file_name)

        Window.clearcolor = (0.2, 0.2, 0.2, 1)
        self.icon = path.join(project_path, "data", "security.png")
        self.root = Factory.RootWindow()

    def visibility_password(self):
        """Change password visibility."""
        if self.root.ids.visibility_switch.active:
            self.root.ids.entry_field.password = False
        else:
            self.root.ids.entry_field.password = True

    def check_password(self):
        """Password check and results display."""
        self.checker.password = self.root.ids.entry_field.text
        password_properties: Dict[str, int] = \
            self.checker.password_properties()

        for key in password_properties:
            minimum_value: int = 0
            status_reverse: bool = False

            if key == "length_amount":
                minimum_value = self.checker.MINIMUM_PASSWORD_LENGTH
            elif key in ("sequential_repetition_amount",
                         "substantial_dominance_amount",
                         "symbol_set_amount"):
                status_reverse = True

            self.root.ids[f"{key}"].text = str(password_properties[f"{key}"])
            self.definition_display_status(password_properties[f"{key}"],
                                           self.root.ids[f"{key[0:-6]}status"],
                                           minimum_value, status_reverse)

        self.root.ids.bit_entropy_status.value = \
            password_properties["bit_entropy_amount"]

    def definition_display_status(self, count_symbol: int, field_status: Image,
                                  minimum_value: int, status_reverse: bool):
        """Definition and display of status."""
        if count_symbol > minimum_value:
            field_status.source = self.NEGATIVE_ICON if status_reverse \
                else self.POSITIVE_ICON
        else:
            field_status.source = self.POSITIVE_ICON if status_reverse \
                else self.NEGATIVE_ICON

    def show_keyboard(self):
        """On-screen keyboard control."""
        if self.root.ids.keyboard_button.state == "down":
            if not self.VIRTUAL_KEYBOARD.target:
                self.VIRTUAL_KEYBOARD.target = self.root.ids.entry_field
                self.VIRTUAL_KEYBOARD.bind(on_textinput=(
                    lambda _, char: self.root.ids.entry_field.insert_text(char)
                ))
                self.VIRTUAL_KEYBOARD.setup_mode()
            self.root.get_root_window().add_widget(self.VIRTUAL_KEYBOARD)
        else:
            self.root.get_root_window().remove_widget(self.VIRTUAL_KEYBOARD)

    def on_pause(self) -> bool:
        """Return the sign of switching to pause mode."""
        return True
