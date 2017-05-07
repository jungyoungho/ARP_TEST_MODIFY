#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>

namespace Ui {
class Widget;
}

class Widget : public QWidget
{
    Q_OBJECT

public:
    explicit Widget(QWidget *parent = 0);
    ~Widget();

private slots:
    void on_Button_500_clicked();

    void on_Button_100_clicked();

    void on_Button_50_clicked();

    void on_Button_10_clicked();

    void on_Button_Yul250_clicked();

    void on_Button_Coffee200_clicked();

    void on_Button_Tea100_clicked();

    void on_Button_Change_clicked();

private:
    Ui::Widget *ui;
};

#endif // WIDGET_H
