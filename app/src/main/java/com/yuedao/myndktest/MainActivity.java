package com.yuedao.myndktest;

import android.os.Bundle;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.yuedao.myndktest.databinding.ActivityMainBinding;
import com.yuedao.winery.ndk.JniUtil;

public class MainActivity extends AppCompatActivity {
    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        TextView tv = binding.sampleText;
        JniUtil.init();
        tv.setText(JniUtil.getKey());
    }
}