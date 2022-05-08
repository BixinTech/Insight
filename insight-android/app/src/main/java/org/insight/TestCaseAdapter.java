package org.insight;

import android.util.Pair;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.util.List;

public class TestCaseAdapter extends RecyclerView.Adapter<TestCaseAdapter.ViewHolder> {

    private List<Pair<String, Runnable>> testCases;

    public TestCaseAdapter(List<Pair<String, Runnable>> testCases) {
        this.testCases = testCases;
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.cell_test_case, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        holder.onBind(testCases.get(position));
    }

    @Override
    public int getItemCount() {
        return testCases.size();
    }

    static class ViewHolder extends RecyclerView.ViewHolder {

        private TextView caseTV;

        public ViewHolder(@NonNull View itemView) {
            super(itemView);

            this.caseTV = itemView.findViewById(R.id.case_tv);
        }

        public void onBind(Pair<String, Runnable> testCase) {
            this.caseTV.setText(testCase.first);
            this.itemView.setOnClickListener(v -> {
                testCase.second.run();
            });
        }
    }
}
