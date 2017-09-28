package edu.buffalo.cse.cse486586.simpledht;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.telephony.TelephonyManager;
import android.util.Log;

import org.apache.http.impl.conn.tsccm.WaitingThreadAborter;

import static android.content.ContentValues.TAG;
import static android.content.Context.TELEPHONY_SERVICE;
import static java.lang.Thread.sleep;

public class SimpleDhtProvider extends ContentProvider {
    public static final String PREFS_NAME = "MyPrefsFile";
    static final String[] PORTS = {"11108", "11112", "11116", "11120", "11124"};
    static final int SERVER_PORT = 10000;
    String myport="";
    String leader ="11108";
    boolean created=false;
    String myhash="";
    String sr;
    String pr;
    int psize=1;
    String[] porttable;
    String[] hashtable;
    ArrayList<String> portlist = new ArrayList<String>();
    Map<String, portob> hmap = new HashMap<String, portob>();
    int counter=0;

    public class portob
    {
        String portno;
        String porthash;
    }


    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        if (psize == 1) {
            SharedPreferences prefs = getContext().getSharedPreferences(PREFS_NAME, 0);
            if (selection.equals("@") || selection.equals("*")) {
                prefs.edit().clear().apply();
            } else {
                prefs.edit().remove(selection).apply();
            }
        } else {
            SharedPreferences prefs = getContext().getSharedPreferences(PREFS_NAME, 0);
            if (selection.equals("@")) {

                prefs.edit().clear().apply();
            } else if (selection.equals("*")) {
                for (int i = 0; i < porttable.length; i++) {
                    Socket socket = null;
                    String remoteport = porttable[i];
                    try {
                        socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                Integer.parseInt(remoteport));
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    String msgToSend = "6$" + selection;
                    OutputStream outToServer = null;

                    try {
                        outToServer = socket.getOutputStream();
                    } catch (IOException e2) {
                        e2.printStackTrace();
                    }
                    DataOutputStream out = new DataOutputStream(outToServer);
                    try {
                        out.writeUTF(msgToSend);
                        Thread.sleep(100);
                        out.flush();
                    } catch (IOException e3) {
                        e3.printStackTrace();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }

                }
            } else {
                String key = selection;
                String hashedkey = null;
                try {
                    hashedkey = genHash(key);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
                String tempport = getport(hashedkey);
                if (tempport.equals(myport)) {
                    prefs.edit().remove(selection).apply();
                } else {
                    Socket socket = null;
                    String remoteport = tempport;
                    try {
                        socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                Integer.parseInt(remoteport));
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    String msgToSend = "7$" + selection;
                    OutputStream outToServer = null;

                    try {
                        outToServer = socket.getOutputStream();
                    } catch (IOException e2) {
                        e2.printStackTrace();
                    }
                    DataOutputStream out = new DataOutputStream(outToServer);
                    try {
                        out.writeUTF(msgToSend);
                        Thread.sleep(100);
                        out.flush();
                    } catch (IOException e3) {
                        e3.printStackTrace();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }

                }
            }



        }
        return 0;
    }




    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub
        return null;
    }


    //#ip
    @Override
    public Uri insert(Uri uri, ContentValues values) {
        if (psize==1)
        {
            SharedPreferences prefs = getContext().getSharedPreferences(PREFS_NAME, 0);
            SharedPreferences.Editor editor = prefs.edit();

            editor.putString(values.getAsString("key"), values.getAsString("value"));
            editor.apply();
            // TODO Auto-generated method stub
            Log.v("insert", values.toString());
            return uri;
        }
        else
        {
            String key = values.getAsString("key");
            try {
                String hashedkey = genHash(key);
            String hashedself = genHash(Integer.toString(Integer.parseInt(myport) / 2));
            String tempport = getport(hashedkey);
                Log.v("Recog:",hashedkey+"  "+tempport);
            if(tempport.equals(myport))
            {
                SharedPreferences prefs = getContext().getSharedPreferences(PREFS_NAME, 0);
                SharedPreferences.Editor editor = prefs.edit();

                editor.putString(values.getAsString("key"), values.getAsString("value"));
                editor.apply();
                // TODO Auto-generated method stub
                Log.v("insert", values.toString());
                return uri;
            }
                else
            {
                String msg = "2$" + values.getAsString("key") + "$" + values.getAsString("value")+"$"+tempport;
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg, myport);
            }

            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }


        }


        return null;
    }



    @Override
    public boolean onCreate() {

        //setContentView(R.layout.activity_group_messenger);

        Context context = this.getContext();
        TelephonyManager tel = (TelephonyManager) context.getSystemService(TELEPHONY_SERVICE);
        String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        final String myPort = String.valueOf((Integer.parseInt(portStr) * 2));
        myport=myPort;
        try {
            myhash=genHash(Integer.toString(Integer.parseInt(myport)/2));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }


        if (Integer.parseInt(myport)==Integer.parseInt("11108"))
        {
            portlist.add(myport);
            portob temp = new portob();
            temp.portno=myport;

            try {
                temp.porthash=genHash(Integer.toString(Integer.parseInt(myport)/2));
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            hmap.put(myport,temp);
        }


        try {

            ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
        }
        catch (IOException e)
        {

            Log.e(TAG, "Can't create a ServerSocket");

        }

        String msg="1$"+myport;
        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg, myPort);


        return false;
    }



    private class ServerTask extends AsyncTask<ServerSocket, String, Void> {

        public Uri buildUri(String scheme, String authority) {
            Uri.Builder uriBuilder = new Uri.Builder();
            uriBuilder.authority(authority);
            uriBuilder.scheme(scheme);
            return uriBuilder.build();
        }



        ContentValues keyValueToInsert = new ContentValues();

        @Override
        protected Void doInBackground(ServerSocket... sockets) {

            ServerSocket serverSocket = sockets[0];

            while (true) {
                try {

                    Socket server = serverSocket.accept();

                    DataInputStream in = new DataInputStream(server.getInputStream());
                    String msg2 = in.readUTF();
                    String[] parts = msg2.split("\\$");
                    int mode = Integer.parseInt(parts[0]);


                    if (mode==1)
                    {
                        String joined_avd = parts[1];
                        portlist.add(joined_avd);
                        String hport="";

                        try {
                            hport = genHash(Integer.toString(Integer.parseInt(parts[1])/2));

                        } catch (NoSuchAlgorithmException e) {
                            e.printStackTrace();
                        }

                        portob temp = new portob();
                        temp.portno=joined_avd;
                        temp.porthash=hport;
                        hmap.put(joined_avd,temp);

                        for(int i=0;i<portlist.size();i++)
                        {
                            String remotePort = portlist.get(i);
                            String table = getsrpr();
                            Socket socket = null;
                            try {
                                socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                        Integer.parseInt(remotePort));
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                            String m = table;
                            OutputStream outToServer = null;

                            try {
                                outToServer = socket.getOutputStream();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                            DataOutputStream out = new DataOutputStream(outToServer);
                            try {
                                out.writeUTF(m);
                                Thread.sleep(100);
                                out.flush();
                            } catch (IOException e) {
                                e.printStackTrace();
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                        }


                    }
                    else if(mode==2)
                    {
                        porttable=totable(msg2);
                        hashtable = gethashtable(porttable);
                        psize++;
                    }

                    else if(mode==3)
                    {
                        String key = parts[1];
                        String value = parts[2];
                        keyValueToInsert.put("key", key);
                        keyValueToInsert.put("value", value);
                        Uri mUri = buildUri("content", "edu.buffalo.cse.cse486586.simpledht.provider");
                        insert(mUri, keyValueToInsert);

                    }

                    else if (mode==4)
                    {
                        String selection = parts[1];
                        OutputStream outToServer = server.getOutputStream();
                        DataOutputStream out = new DataOutputStream(outToServer);
                        SharedPreferences prefs = getContext().getSharedPreferences(PREFS_NAME, 0);
                        String value = prefs.getString(selection, "");
                        out.writeUTF(value);
                        Thread.sleep(100);
                        out.flush();

                    }
                    else if (mode==5)
                    {

                        OutputStream outToServer = server.getOutputStream();
                        DataOutputStream out = new DataOutputStream(outToServer);
                        SharedPreferences prefs = getContext().getSharedPreferences(PREFS_NAME, 0);
                        Map star = prefs.getAll();
                        Log.v("Pref size",Integer.toString(star.size()));
                        Set keys = star.keySet();
                        String output="";
                        for (Iterator i = keys.iterator(); i.hasNext(); ) {
                            String key = (String) i.next();
                            String value = (String) star.get(key);
                            Log.v("P: ",key+" "+value);
                            output=output+key+"$"+value+"$";
                        }

                        out.writeUTF(output);
                        Thread.sleep(100);
                        out.flush();
                    }

                    else if(mode==6)
                    {
                        SharedPreferences prefs = getContext().getSharedPreferences(PREFS_NAME, 0);
                        prefs.edit().clear().apply();
                    }

                    else if(mode==7)
                    {
                        String selection=parts[1];
                        SharedPreferences prefs = getContext().getSharedPreferences(PREFS_NAME, 0);
                        prefs.edit().remove(selection).apply();
                    }

                    //Log.v("Received:", msg2);
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }

    }






    private class ClientTask extends AsyncTask<String, Void, Void> {
        @Override
        protected Void doInBackground(String... msgs) {

            String[] parts = msgs[0].split("\\$");
            int mode = Integer.parseInt(parts[0]);
            if (mode==1) {
                Socket socket = null;
                // Join message
                if (created == false && Integer.parseInt(myport) != Integer.parseInt(leader)) {
                    created = true;
                    try {
                        socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                Integer.parseInt(leader));
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    String msgToSend = "1$" + myport;

                    OutputStream outToServer = null;

                    try {
                        outToServer = socket.getOutputStream();
                    } catch (IOException e2) {
                        e2.printStackTrace();
                    }
                    DataOutputStream out = new DataOutputStream(outToServer);
                    try {
                        out.writeUTF(msgToSend);
                        Thread.sleep(100);
                        out.flush();
                    } catch (IOException e3) {
                        e3.printStackTrace();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }

            else if(mode==2)
            {
                String key=parts[1];
                String value = parts[2];
                Socket socket = null;
                String remoteport = parts[3];
                    try {
                        socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                Integer.parseInt(remoteport));
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    String msgToSend = "3$" + key+"$"+value;

                    OutputStream outToServer = null;

                    try {
                        outToServer = socket.getOutputStream();
                    } catch (IOException e2) {
                        e2.printStackTrace();
                    }
                    DataOutputStream out = new DataOutputStream(outToServer);
                    try {
                        out.writeUTF(msgToSend);
                        Thread.sleep(100);
                        out.flush();
                    } catch (IOException e3) {
                        e3.printStackTrace();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
            }


            return null;
        }

    }


    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {

        if(psize==1) {
            SharedPreferences prefs = getContext().getSharedPreferences(PREFS_NAME, 0);
            if (selection.equals("@")) {
                Map localmap = prefs.getAll();
                String cnames[] = {"key", "value"};
                MatrixCursor matrixCursor = new MatrixCursor(cnames, 2);
                Set keys = localmap.keySet();
                for (Iterator i = keys.iterator(); i.hasNext(); ) {
                    String key = (String) i.next();
                    String value = (String) localmap.get(key);
                    String keyvalue[] = {key, value};
                    matrixCursor.addRow(keyvalue);

                }
                return matrixCursor;

            } else if (selection.equals("*")) {
                Map localmap = prefs.getAll();
                String cnames[] = {"key", "value"};
                MatrixCursor matrixCursor = new MatrixCursor(cnames, 2);
                Set keys = localmap.keySet();
                for (Iterator i = keys.iterator(); i.hasNext(); ) {
                    String key = (String) i.next();
                    String value = (String) localmap.get(key);
                    String keyvalue[] = {key, value};
                    matrixCursor.addRow(keyvalue);

                }
                return matrixCursor;
            } else {

                String key = selection;

                String value = prefs.getString(selection, "");
                String cnames[] = {"key", "value"};
                MatrixCursor matrixCursor = new MatrixCursor(cnames, 2);
                String keyvalue[] = {selection, value};
                matrixCursor.addRow(keyvalue);

                return matrixCursor;
            }
        }

        else {
            SharedPreferences prefs = getContext().getSharedPreferences(PREFS_NAME, 0);

            if (selection.equals("@")) {
                Map localmap = prefs.getAll();
                String cnames[] = {"key", "value"};
                MatrixCursor matrixCursor = new MatrixCursor(cnames, 2);
                Set keys = localmap.keySet();
                for (Iterator i = keys.iterator(); i.hasNext(); ) {
                    String key = (String) i.next();
                    String value = (String) localmap.get(key);
                    String keyvalue[] = {key, value};
                    matrixCursor.addRow(keyvalue);

                }
                return matrixCursor;

            }
            else if(selection.equals("*"))
            {
                String Output ="";
                for (int i=0;i<porttable.length;i++)
                {
                    Socket socket = null;
                    String remoteport = porttable[i];
                    try {
                        socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                Integer.parseInt(remoteport));
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    String msgToSend = "5$" +selection;
                    OutputStream outToServer = null;

                    try {
                        outToServer = socket.getOutputStream();
                    } catch (IOException e2) {
                        e2.printStackTrace();
                    }
                    DataOutputStream out = new DataOutputStream(outToServer);
                    try {
                        out.writeUTF(msgToSend);
                        Thread.sleep(100);
                        out.flush();
                    } catch (IOException e3) {
                        e3.printStackTrace();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }

                    DataInputStream in = null;
                    try {
                        in = new DataInputStream(socket.getInputStream());
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    try {
                        String output = in.readUTF();
                        Output=Output+output;

                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                Map<String,String> star = getstar(Output);
                String cnames[] = {"key", "value"};
                MatrixCursor matrixCursor = new MatrixCursor(cnames, 2);
                Set keys = star.keySet();
                for (Iterator i = keys.iterator(); i.hasNext(); ) {
                    String key = (String) i.next();
                    String value = (String) star.get(key);
                    String keyvalue[] = {key, value};
                    matrixCursor.addRow(keyvalue);

                }
                Log.v("Number of rows",Integer.toString(star.size()));
                return matrixCursor;

            }
            else {
                String key= selection;
                String hashedkey = null;
                try {
                    hashedkey = genHash(key);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
                String tempport = getport(hashedkey);
                if(tempport.equals(myport))
                {
                    String value = prefs.getString(selection, "");
                    String cnames[] = {"key", "value"};
                    MatrixCursor matrixCursor = new MatrixCursor(cnames, 2);
                    String keyvalue[] = {selection, value};
                    matrixCursor.addRow(keyvalue);

                    return matrixCursor;
                }
                else
                {
                    Socket socket = null;
                    String remoteport = tempport;
                    try {
                        socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                Integer.parseInt(remoteport));
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    String msgToSend = "4$" +selection;
                    OutputStream outToServer = null;

                    try {
                        outToServer = socket.getOutputStream();
                    } catch (IOException e2) {
                        e2.printStackTrace();
                    }
                    DataOutputStream out = new DataOutputStream(outToServer);
                    try {
                        out.writeUTF(msgToSend);
                        Thread.sleep(100);
                        out.flush();
                    } catch (IOException e3) {
                        e3.printStackTrace();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }

                    try {
                        DataInputStream in = new DataInputStream(socket.getInputStream());
                        String output = in.readUTF();
                        counter=counter+1;
                        //Log.v("output received:",output+" "+Integer.toString(counter));
                        String cnames[] = {"key", "value"};
                        MatrixCursor matrixCursor = new MatrixCursor(cnames, 2);
                        String keyvalue[] = {selection, output};
                        matrixCursor.addRow(keyvalue);
                        return matrixCursor;

                    } catch (IOException e) {
                        e.printStackTrace();
                    }


                }
            }

            return null;
        }
    }




    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        return 0;
    }

    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

    private String getsrpr()
    {

        List<portob> sortedhash = new ArrayList<portob>(hmap.values());
        Collections.sort(sortedhash, new Comparator<portob>() {
            @Override
            public int compare(portob s, portob t1) {
                if (s.porthash.compareTo(t1.porthash)>0)
                {
                    return 1;
                }
                else
                {
                    return -1;
                }
            }
        });


        String table="2$";
        for (int i=0;i<sortedhash.size();i++)
        {
            table=table+sortedhash.get(i).portno+"$";
        }


        return table;
    }

    private String[] totable(String s)
    {

        String[] parts = s.split("\\$");
        String[] table = new String[(parts.length -1)];

        for(int i=1;i<parts.length;i++)
        {
            table[i-1]=parts[i];
        }


        return table;
    }

    private String[] gethashtable(String[] a)
    {
        String output[]=new String[a.length];
        for(int i=0;i<a.length;i++)
        {
            try {
                output[i]=genHash(Integer.toString(Integer.parseInt(a[i]) / 2));

            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }


        return output;
    }

    private String getport(String hkey)
    {
        String tempport="";
        boolean found = false;

        for (int i=0;i<porttable.length;i++)
        {

            if(hashtable[i].compareTo(hkey)>0)
            {

                tempport=porttable[i];
                found = true;
                break;
            }
        }

        if(found==false)
        {
            tempport=porttable[0];
        }


        return tempport;
    }


    private Map getstar(String s)
    {
        Map<String,String> star=new HashMap<String, String>();

        String[] parts = s.split("\\$");
        Log.v("Parts: ",Integer.toString(parts.length));
        int n = parts.length/2;
        Log.v("n: ",Integer.toString(n));
        for(int i=0;i<parts.length;i++)
        {
            Log.v("S: ",parts[i]+" "+parts[i+1]);
            star.put(parts[i],parts[i+1]);
            i++;
        }

        return star;
    }



}