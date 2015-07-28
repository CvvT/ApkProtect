package com.cc.test;

import android.app.Activity;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;


public class MainActivity extends Activity {

    static {
        ProxyShell.startshell("com.cc.test");
    }

    String str = "A Text From CwT";
    public static int cwt = 100;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        TextView text = (TextView)findViewById(R.id.textview);
        text.setText(str);
        text.setText("this is a test");
        final EditText edit = (EditText)findViewById(R.id.editText);
        Button button = (Button)findViewById(R.id.button);
        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String str = edit.getText().toString();
                if (str != null && !str.equals(""))
                    if (str.equals("flag"))
                        Toast.makeText(MainActivity.this, "Correct", Toast.LENGTH_SHORT).show();
                    else
                        Toast.makeText(MainActivity.this, "Wrong", Toast.LENGTH_SHORT).show();
            }
        });
    }

    public boolean easyTest(){
        String test = "This is a easy test";
        Boolean flag = false;
        if (test.equals("This is a test")){
            flag = true;
        }
        return flag;
    }

    public boolean Test(){
        Boolean flag = false;
        String number = "100";
        try {
            int num = Integer.valueOf(number);
            flag = true;
        } catch (Exception e){
            e.printStackTrace();
        }
        return flag;
    }

    public void addmethod(){
        return;
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}
