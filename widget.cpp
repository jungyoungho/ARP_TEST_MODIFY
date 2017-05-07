#include "widget.h"
#include "ui_widget.h"
#include "QString"

Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);
    QString str = ui->lineEdit->text();
    int n =str.toInt();
    if(n<250)
        ui->Button_Yul250->setDisabled(true);
    if(n<200)
        ui->Button_Coffee200->setDisabled(true);
    if(n<100)
        ui->Button_Tea100->setDisabled(true);
}

Widget::~Widget()
{

    delete ui;
}
//--------------------------------------------------coin part
void Widget::on_Button_500_clicked()
{
    QString str500 = ui->lineEdit->text();
    int n = str500.toInt();
    n=n+500;
    if(n>=250)
         ui->Button_Yul250->setEnabled(true);
    if(n>=200)
         ui->Button_Coffee200->setEnabled(true);
    if(n>=100)
         ui->Button_Tea100->setEnabled(true);
    QString output = QString::number(n);
    ui->lineEdit->setText(output);

}

void Widget::on_Button_100_clicked()
{
    QString str100 = ui->lineEdit->text();
    int n = str100.toInt();
    n=n+100;
    if(n>=250)
         ui->Button_Yul250->setEnabled(true);
    if(n>=200)
         ui->Button_Coffee200->setEnabled(true);
    if(n>=100)
         ui->Button_Tea100->setEnabled(true);
    QString output = QString::number(n);
    ui->lineEdit->setText(output);
}

void Widget::on_Button_50_clicked()
{
    QString str50 = ui->lineEdit->text();
    int n = str50.toInt();
    n=n+50;
    if(n>=250)
         ui->Button_Yul250->setEnabled(true);
    if(n>=200)
         ui->Button_Coffee200->setEnabled(true);
   if(n>=100)
         ui->Button_Tea100->setEnabled(true);
    QString output = QString::number(n);
    ui->lineEdit->setText(output);
}

void Widget::on_Button_10_clicked()
{
    QString str10 = ui->lineEdit->text();
    int n = str10.toInt();
    n=n+10;
    if(n>=250)
         ui->Button_Yul250->setEnabled(true);
    if(n>=200)
         ui->Button_Coffee200->setEnabled(true);
    if(n>=100)
         ui->Button_Tea100->setEnabled(true);
    QString output = QString::number(n);
    ui->lineEdit->setText(output);
}
//--------------------------------------------------coin part

//--------------------------------------------------good part


void Widget::on_Button_Yul250_clicked()
{
    QString strYul = ui->lineEdit->text();
    int n = strYul.toInt();
    n=n-250;
    if(n>=0)
    {
        QString output = QString::number(n);
        ui->lineEdit->setText(output);
    }
    if(n<250)
         ui->Button_Yul250->setDisabled(true);
    if(n<200)
         ui->Button_Coffee200->setDisabled(true);
    if(n<100)
         ui->Button_Tea100->setDisabled(true);
}

void Widget::on_Button_Coffee200_clicked()
{
    QString strCoffee = ui->lineEdit->text();
    int n = strCoffee.toInt();
    n=n-200;
    if(n>=0)
    {
        QString output = QString::number(n);
        ui->lineEdit->setText(output);
    }
    if(n<250)
         ui->Button_Yul250->setDisabled(true);
    if(n<200)
         ui->Button_Coffee200->setDisabled(true);
    if(n<100)
         ui->Button_Tea100->setDisabled(true);
}

void Widget::on_Button_Tea100_clicked()
{
    QString strTea = ui->lineEdit->text();
    int n = strTea.toInt();
    n=n-100;
    if(n>=0)
    {
        QString output = QString::number(n);
        ui->lineEdit->setText(output);
    }
    if(n<250)
         ui->Button_Yul250->setDisabled(true);
    if(n<200)
         ui->Button_Coffee200->setDisabled(true);
    if(n<100)
         ui->Button_Tea100->setDisabled(true);
}

void Widget::on_Button_Change_clicked()
{
    QString strChange = ui->lineEdit->text();
    int n = strChange.toInt();
    if(n>=500)
    {
        n=n-500;
    }
    else if(n>=100)
    {
        n=n-100;
    }
    else if(n>=50)
    {
        n=n-50;
    }
    else if(n>=10)
    {
        n=n-10;
    }
    if(n>=0)
    {
        QString output = QString::number(n);
        ui->lineEdit->setText(output);
    }
}
