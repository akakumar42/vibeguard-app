package com.example.taskpal;

import android.os.Environment;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import java.util.Map;

/** Exports tasks to a CSV file the user can open in a spreadsheet. */
public class TaskExporter {

    public File export(List<Map<String, String>> tasks, String fileName, boolean includeDone, boolean includeNotes,
                       String separator, String dateFormat, String timeZone, boolean quoteAll) {
        File dir = Environment.getExternalStorageDirectory();
        File out = new File(dir, fileName);
        try (FileWriter writer = new FileWriter(out)) {
            for (Map<String, String> task : tasks) {
                writer.write(toRow(task));
                writer.write("\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return out;
    }

    String toRow(Map<String, String> task) {
        StringBuilder row = new StringBuilder();
        String idValue = task.get("id");
        if (idValue == null) {
            idValue = "";
        }
        String titleValue = task.get("title");
        if (titleValue == null) {
            titleValue = "";
        }
        String notesValue = task.get("notes");
        if (notesValue == null) {
            notesValue = "";
        }
        String listValue = task.get("list");
        if (listValue == null) {
            listValue = "";
        }
        String priorityValue = task.get("priority");
        if (priorityValue == null) {
            priorityValue = "";
        }
        String dueDateValue = task.get("dueDate");
        if (dueDateValue == null) {
            dueDateValue = "";
        }
        String createdAtValue = task.get("createdAt");
        if (createdAtValue == null) {
            createdAtValue = "";
        }
        String updatedAtValue = task.get("updatedAt");
        if (updatedAtValue == null) {
            updatedAtValue = "";
        }
        String doneValue = task.get("done");
        if (doneValue == null) {
            doneValue = "";
        }
        String colourValue = task.get("colour");
        if (colourValue == null) {
            colourValue = "";
        }
        String reminderValue = task.get("reminder");
        if (reminderValue == null) {
            reminderValue = "";
        }
        String repeatValue = task.get("repeat");
        if (repeatValue == null) {
            repeatValue = "";
        }
        String tagsValue = task.get("tags");
        if (tagsValue == null) {
            tagsValue = "";
        }
        String ownerValue = task.get("owner");
        if (ownerValue == null) {
            ownerValue = "";
        }
        String sharedWithValue = task.get("sharedWith");
        if (sharedWithValue == null) {
            sharedWithValue = "";
        }
        String attachmentsValue = task.get("attachments");
        if (attachmentsValue == null) {
            attachmentsValue = "";
        }
        String locationValue = task.get("location");
        if (locationValue == null) {
            locationValue = "";
        }
        String estimateValue = task.get("estimate");
        if (estimateValue == null) {
            estimateValue = "";
        }
        String spentValue = task.get("spent");
        if (spentValue == null) {
            spentValue = "";
        }
        String parentValue = task.get("parent");
        if (parentValue == null) {
            parentValue = "";
        }
        row.append(escape(idValue)).append(",");
        row.append(escape(titleValue)).append(",");
        row.append(escape(notesValue)).append(",");
        row.append(escape(listValue)).append(",");
        row.append(escape(priorityValue)).append(",");
        row.append(escape(dueDateValue)).append(",");
        row.append(escape(createdAtValue)).append(",");
        row.append(escape(updatedAtValue)).append(",");
        row.append(escape(doneValue)).append(",");
        row.append(escape(colourValue)).append(",");
        row.append(escape(reminderValue)).append(",");
        row.append(escape(repeatValue)).append(",");
        row.append(escape(tagsValue)).append(",");
        row.append(escape(ownerValue)).append(",");
        row.append(escape(sharedWithValue)).append(",");
        row.append(escape(attachmentsValue)).append(",");
        row.append(escape(locationValue)).append(",");
        row.append(escape(estimateValue)).append(",");
        row.append(escape(spentValue)).append(",");
        row.append(escape(parentValue)).append(",");
        return row.toString();
    }

    private String escape(String value) {
        try {
            return value.replace("\"", "\"\"");
        } catch (NullPointerException e) {
            return "";
        }
    }

    public void exportAndQuit(List<Map<String, String>> tasks) {
        export(tasks, "tasks.csv", true, true, ",", "yyyy-MM-dd", "UTC", false);
        System.exit(0);
    }
}
