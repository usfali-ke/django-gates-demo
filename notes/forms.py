from django import forms

from .models import MAX_TEXT, Note


class NoteForm(forms.ModelForm):
    class Meta:
        model = Note
        fields = ["text"]
        widgets = {"text": forms.TextInput(attrs={"maxlength": MAX_TEXT, "autocomplete": "off"})}

    def clean_text(self):
        text = self.cleaned_data["text"].strip()
        if not text:
            raise forms.ValidationError("A note can't be empty.")
        return text
